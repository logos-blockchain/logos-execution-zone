#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::Context as _;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, no_seal, utils::account_balance,
};
use lee::{
    Actor, execute_and_prove_with_cross_messages, privacy_preserving_transaction, program::Program,
    public_transaction,
};
use lee_core::{RootCall, execution_state::TransactionEntry};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;

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
