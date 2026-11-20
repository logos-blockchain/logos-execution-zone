#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context as _, bail, ensure};
use bridge_core::{DepositMetadata, DepositRecipient};
use chain_state::vault::VAULT_PROGRAM;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, no_seal,
    utils::{account_balance, get_account, wait_for_indexer_to_catch_up, wait_until},
};
use lee::{
    AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey,
    execute_and_prove_with_cross_messages, privacy_preserving_transaction, program::Program,
    public_transaction,
};
use lee_core::{RootCall, execution_state::TransactionEntry};
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    binary_codec::canonical::BinaryEncode as _,
    core::mantle::{
        Value,
        gas::GasCost,
        ops::channel::{deposit::Metadata, inscribe::Step},
    },
    http_api_common::{
        bodies::channel::{
            ChannelDepositRequestBody, ChannelPrepareDepositResponseBody, ChannelStepRequestBody,
            ProgramDepositBody,
        },
        paths::CHANNEL_PREPARE_DEPOSIT,
    },
    node_types::Inscription,
};
use sequencer_service_rpc::{HexBytes, RpcClient as _};
use test_fixtures::config::{
    CHANNEL_SIGNING_KEY, UrlProtocol, addr_to_url, bedrock_channel_id, bedrock_funding_key,
};
use tokio::test;
use vault_circuit::{Committee, Deposit, SigningKey};

/// The indexer's reads, apart from the sequencer's methods of the same names.
mod indexed {
    use anyhow::Context as _;
    use indexer_service_rpc::RpcClient as _;
    use integration_tests::TestContext;
    use lee::AccountId;

    pub async fn account(
        ctx: &TestContext,
        account_id: AccountId,
    ) -> anyhow::Result<Option<indexer_service_protocol::Account>> {
        ctx.indexer_client()
            .get_account(account_id.into())
            .await
            .context("Failed to read the account from the indexer")
    }
}

/// Has the Bedrock test node's wallet pay `amount` into the zone's channel and deposit it to the
/// vault for `recipient`. Returns the deposit as the sequencer takes it: the step, then its proof.
async fn program_deposit(
    ctx: &TestContext,
    recipient: PublicKey,
    amount: u64,
) -> anyhow::Result<Vec<u8>> {
    let node = CommonHttpClient::new(None);
    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.bedrock_addr())?;
    let holder = bedrock_funding_key();

    let prepared: ChannelPrepareDepositResponseBody = node
        .post(
            bedrock_url.join(CHANNEL_PREPARE_DEPOSIT.trim_start_matches('/'))?,
            &ChannelDepositRequestBody {
                tip: None,
                channel_id: bedrock_channel_id(),
                amount,
                holder_public_key: holder,
                metadata: Metadata::default(),
                change_public_key: holder,
                funding_public_keys: vec![holder],
                max_tx_fee: GasCost::new(Value::MAX),
            },
        )
        .await
        .context("Failed to prepare the payment into the channel")?;
    node.post_transaction(bedrock_url.clone(), prepared.transaction)
        .await
        .context("Failed to pay into the channel")?;

    let recipient = DepositRecipient::Identified(PublicAccountEvidence::Key(recipient));
    // The vault of the one sequencer of the test.
    let committee = Committee {
        threshold: 1,
        signers: vec![SigningKey::from_channel_seed(&CHANNEL_SIGNING_KEY).public_key()],
    };
    let intent = Deposit {
        value: amount,
        recipient: Deposit::recipient_element(recipient.account_id().value()),
    }
    .intent(committee.id());
    let inscription = Inscription::try_new(borsh::to_vec(&DepositMetadata { recipient })?, 128)
        .ok()
        .context("The recipient does not fit the deposit's inscription")?;

    // The wallet proves the step once it holds the channel note.
    let request = || ChannelStepRequestBody {
        tip: None,
        channel_id: bedrock_channel_id(),
        appended: Vec::new(),
        payments: Vec::new(),
        program_deposit: Some(ProgramDepositBody {
            program_id: *VAULT_PROGRAM,
            value: amount,
            intent,
        }),
        inscription: inscription.clone(),
        change_public_key: holder,
        holder_public_keys: vec![holder],
    };
    let mut attempts = 0_u32;
    let step = loop {
        match node.channel_step(bedrock_url.clone(), request()).await {
            Ok(step) => break step,
            Err(err) if attempts >= 120 => {
                return Err(err).context("The wallet never proved the deposit step");
            }
            Err(_) => {
                attempts = attempts.saturating_add(1);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };
    let Step::ProgramDeposit(deposit) = step.step else {
        bail!("The node answered with a step that is no program deposit");
    };

    let mut bytes = Vec::new();
    deposit.encode_into(&mut bytes);
    step.proof.encode_into(&mut bytes);
    Ok(bytes)
}

#[test]
async fn a_vault_deposit_is_minted_exactly_once() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;
    let recipient = PublicKey::new_from_private_key(&PrivateKey::new_os_random());
    let recipient_id = AccountId::from(&recipient);
    let amount = 1_000_u64;

    let deposit = program_deposit(&ctx, recipient, amount).await?;
    ctx.sequencer_client()
        .submit_program_deposit(HexBytes(deposit.clone()))
        .await
        .context("The sequencer refused the deposit")?;

    wait_until("the deposit to credit its recipient", || async {
        Ok(account_balance(&ctx, recipient_id).await? >= u128::from(amount))
    })
    .await?;
    ensure!(
        ctx.sequencer_client()
            .submit_program_deposit(HexBytes(deposit))
            .await
            .is_err(),
        "A minted deposit was admitted again"
    );

    // The indexer applies the block only if it finds the deposit in the block's inscription.
    wait_for_indexer_to_catch_up(&ctx).await?;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    ensure!(
        account_balance(&ctx, recipient_id).await? == u128::from(amount),
        "The deposit credited its recipient more than once"
    );
    let indexed = indexed::account(&ctx, recipient_id).await?;
    ensure!(
        indexed == Some(get_account(&ctx, recipient_id).await?.into()),
        "The indexer and the sequencer disagree on the recipient: {indexed:?}"
    );

    Ok(())
}

#[test]
async fn public_bridge_deposit_invocation_is_dropped() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let bridge_account_id = system_accounts::bridge_account_id();
    let receipt_id =
        bridge_core::deposit_receipt_account_id(programs::bridge_account_id(), [0_u8; 32]);

    let receipt = Actor::new(receipt_id, programs::bridge_account_id());
    let message = public_transaction::Message::try_new(
        receipt,
        vec![
            receipt,
            Actor::native_balance(bridge_account_id),
            Actor::native_balance(recipient_id),
        ],
        BTreeMap::new(),
        bridge_core::Message::Deposit {
            l1_deposit_op_id: [0_u8; 32],
            recipient_id,
            amount: 1,
        },
    )
    .context("Failed to build public bridge deposit transaction")?;

    let attack_tx = LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));

    let bridge_balance_before = account_balance(&ctx, bridge_account_id).await?;
    let recipient_balance_before = account_balance(&ctx, recipient_id).await?;

    let tx_hash = ctx.sequencer_client().send_transaction(attack_tx).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let bridge_balance_after = account_balance(&ctx, bridge_account_id).await?;
    let recipient_balance_after = account_balance(&ctx, recipient_id).await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(bridge_balance_after, bridge_balance_before);
    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert!(
        tx_on_chain.is_none(),
        "Direct public bridge::Deposit invocation should be rejected"
    );

    Ok(())
}

#[test]
async fn public_bridge_deposit_with_zero_amount_is_rejected() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let bridge_account_id = system_accounts::bridge_account_id();
    let receipt_id =
        bridge_core::deposit_receipt_account_id(programs::bridge_account_id(), [0_u8; 32]);

    let receipt = Actor::new(receipt_id, programs::bridge_account_id());
    let message = public_transaction::Message::try_new(
        receipt,
        vec![
            receipt,
            Actor::native_balance(bridge_account_id),
            Actor::native_balance(recipient_id),
        ],
        BTreeMap::new(),
        bridge_core::Message::Deposit {
            l1_deposit_op_id: [0_u8; 32],
            recipient_id,
            amount: 0,
        },
    )
    .context("Failed to build zero-amount public bridge deposit transaction")?;

    let attack_tx = LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));

    let bridge_balance_before = ctx
        .sequencer_client()
        .get_account_balance(bridge_account_id)
        .await?;
    let recipient_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient_id)
        .await?;

    let tx_hash = ctx.sequencer_client().send_transaction(attack_tx).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let bridge_balance_after = ctx
        .sequencer_client()
        .get_account_balance(bridge_account_id)
        .await?;
    let recipient_balance_after = ctx
        .sequencer_client()
        .get_account_balance(recipient_id)
        .await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(bridge_balance_after, bridge_balance_before);
    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert!(
        tx_on_chain.is_none(),
        "Public bridge::Deposit with zero amount should be rejected"
    );

    Ok(())
}

#[test]
async fn private_bridge_deposit_invocation_is_dropped() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let bridge_account_id = system_accounts::bridge_account_id();
    let receipt_id =
        bridge_core::deposit_receipt_account_id(programs::bridge_account_id(), [0_u8; 32]);

    let programs = lee::privacy_preserving_transaction::circuit::ProgramCatalog::from([(
        programs::bridge_account_id(),
        programs::bridge(),
    )]);

    // Serialize the bridge deposit message
    let deposit = Program::serialize_message(bridge_core::Message::Deposit {
        l1_deposit_op_id: [0_u8; 32],
        recipient_id,
        amount: 1,
    })
    .context("Failed to serialize bridge deposit message")?;

    let receipt = Actor::new(receipt_id, programs::bridge_account_id());
    let public_actors = vec![
        receipt,
        Actor::native_balance(bridge_account_id),
        Actor::native_balance(recipient_id),
    ];

    // Execute and prove the bridge deposit
    // Proven without running the deposit, which settlement refuses.
    let (output, proof) = execute_and_prove_with_cross_messages(
        lee::ProvingInput {
            claims: Vec::new(),
            root: TransactionEntry::Sync(RootCall {
                to: receipt,
                message: deposit,
            }),
            public_context: lee::PublicExecutionContext::new(public_actors, []),
            private_witnesses: Vec::new(),
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
            fee: None,
        },
        // The receipt's own delivery is the one public output; it sends nothing private.
        vec![Vec::new()],
        &programs,
        |_| lee::SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .context("Failed to execute/prove bridge deposit")?;

    // Create privacy-preserving transaction from circuit output
    let message =
        privacy_preserving_transaction::Message::from_circuit_output(BTreeMap::new(), output);

    let witness_set = privacy_preserving_transaction::WitnessSet::for_message(&message, proof, &[]);
    let attack_tx = LeeTransaction::PrivacyPreserving(lee::PrivacyPreservingTransaction::new(
        message,
        witness_set,
    ));

    let bridge_balance_before = account_balance(&ctx, bridge_account_id).await?;
    let recipient_balance_before = account_balance(&ctx, recipient_id).await?;

    // The attack carries no in-proof fee, so admission already refuses it; were it admitted, the
    // bridge program would drop the private invocation at settlement.
    let refused = ctx.sequencer_client().send_transaction(attack_tx).await;
    assert!(
        refused.is_err(),
        "Privacy-preserving bridge::Deposit invocation should be rejected, got {refused:?}"
    );

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let bridge_balance_after = account_balance(&ctx, bridge_account_id).await?;
    let recipient_balance_after = account_balance(&ctx, recipient_id).await?;

    assert_eq!(bridge_balance_after, bridge_balance_before);
    assert_eq!(recipient_balance_after, recipient_balance_before);

    Ok(())
}

// TODO: Bedrock deposit and withdraw tests return with the vault program.
