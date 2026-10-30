#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context as _, ensure};
use bridge_core::{DepositMetadata, DepositRecipient};
use common::transaction::LeeTransaction;
use futures::StreamExt as _;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, no_seal, utils::account_balance,
};
use lee::{
    AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey,
    execute_and_prove_with_cross_messages, privacy_preserving_transaction, program::Program,
    public_transaction,
};
use lee_core::{RootCall, execution_state::TransactionEntry};
use logos_blockchain_core::mantle::{
    Note, Value,
    gas::GasCost,
    ledger::{Inputs, NoteId, Utxo},
    ops::{OpId as _, OpRef, channel::deposit::DepositOp},
};
use logos_blockchain_http_api_common::{
    bodies::{
        channel::{ChannelDepositRequestBody, ChannelDepositResponseBody},
        wallet::transfer_funds::WalletTransferFundsRequestBody,
    },
    paths::CHANNEL_DEPOSIT,
};
use logos_blockchain_zone_sdk::{CommonHttpClient, node_types::ApiBlock};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::config::{UrlProtocol, addr_to_url, bedrock_channel_id, bedrock_funding_key};
use tokio::test;

// A pinning block waits for the sequencer's next committee turn.
const TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK: Duration = Duration::from_mins(5);

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

/// Deposits `amount` from the Bedrock test node's wallet into the zone's
/// channel for `recipient` and returns the channel note the deposit re-creates.
async fn submit_bedrock_deposit(
    ctx: &TestContext,
    recipient: PublicKey,
    amount: u64,
) -> anyhow::Result<NoteId> {
    let node = CommonHttpClient::new(None);
    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.bedrock_addr())?;
    let funding_key = bedrock_funding_key();

    let exact_note = async || -> anyhow::Result<_> {
        let balance = node
            .get_wallet_balance(bedrock_url.clone(), funding_key, None)
            .await
            .context("Failed to query the Bedrock wallet balance")?;
        Ok(balance
            .notes
            .iter()
            .find_map(|(note_id, value)| (*value == amount).then_some(*note_id)))
    };

    let mut note_id = exact_note().await?;
    if note_id.is_none() {
        node.transfer_funds(
            bedrock_url.clone(),
            WalletTransferFundsRequestBody {
                tip: None,
                change_public_key: funding_key,
                funding_public_keys: vec![funding_key],
                recipient_public_key: funding_key,
                amount,
            },
        )
        .await
        .context("Failed to split off a note of the deposit amount")?;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            note_id = exact_note().await?;
            if note_id.is_some() {
                break;
            }
        }
    }
    let note_id = note_id.context("The Bedrock wallet never held a note of the deposit amount")?;

    let metadata = borsh::to_vec(&DepositMetadata {
        recipient: DepositRecipient::Identified(PublicAccountEvidence::Key(recipient)),
    })?
    .try_into()
    .map_err(|_err| anyhow::anyhow!("deposit metadata is too big"))?;
    let deposit = DepositOp {
        channel_id: bedrock_channel_id(),
        inputs: Inputs::new(note_id),
        metadata,
    };
    let deposited_note = Utxo::new(deposit.op_id(), 0, Note::new(amount, funding_key)).id();
    let _: ChannelDepositResponseBody = node
        .post(
            bedrock_url.join(CHANNEL_DEPOSIT.trim_start_matches('/'))?,
            &ChannelDepositRequestBody {
                tip: None,
                deposit,
                change_public_key: funding_key,
                funding_public_keys: vec![funding_key],
                max_tx_fee: GasCost::new(Value::MAX),
            },
        )
        .await
        .context("Failed to submit the Bedrock deposit")?;

    Ok(deposited_note)
}

/// Whether `block` carries a channel inscription bundled with a transfer that
/// spends `note`, which only a block pinned on that deposited note does.
fn pins_note(block: &ApiBlock, note: NoteId) -> bool {
    let channel_id = bedrock_channel_id();
    block.transactions.iter().any(|tx| {
        tx.op_refs_iter().any(|op| {
            matches!(op, OpRef::ChannelInscribe(inscribe) if inscribe.channel_id == channel_id)
        }) && tx.op_refs_iter().any(|op| {
            matches!(
                op,
                OpRef::ChannelTransfer(transfer)
                    if transfer.channel_id == channel_id
                        && transfer.inputs.iter().any(|input| *input == note)
            )
        })
    })
}

/// A deposit is minted in a block published together with a transfer that
/// spends the deposit's channel note, and its finalization does not mint it
/// again.
#[test]
async fn a_bedrock_deposit_is_minted_in_a_block_pinned_on_it_and_only_once() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;
    let recipient = PublicKey::new_from_private_key(&PrivateKey::new_os_random());
    let recipient_id = AccountId::from(&recipient);
    let amount = 1_u64;

    // Subscribed before the deposit, so no block after it is missed.
    let blocks = CommonHttpClient::new(None)
        .get_blocks_stream(addr_to_url(UrlProtocol::Http, ctx.bedrock_addr())?)
        .await
        .context("Failed to subscribe to Bedrock blocks")?;
    let mut blocks = std::pin::pin!(blocks);
    let deposited_note = submit_bedrock_deposit(&ctx, recipient, amount).await?;

    let pinned_at = tokio::time::timeout(TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK, async {
        while let Some(event) = blocks.next().await {
            if pins_note(&event.block, deposited_note) {
                return anyhow::Ok(u64::from(event.block.header.slot));
            }
        }
        anyhow::bail!("The Bedrock block stream ended")
    })
    .await
    .context("No block was published pinned on the deposit")??;

    tokio::time::timeout(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS), async {
        while account_balance(&ctx, recipient_id).await? != u128::from(amount) {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        anyhow::Ok(())
    })
    .await
    .context("The pinned block did not credit the deposit")??;

    tokio::time::timeout(TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK, async {
        while let Some(event) = blocks.next().await {
            if u64::from(event.lib_slot) >= pinned_at {
                return anyhow::Ok(());
            }
        }
        anyhow::bail!("The Bedrock block stream ended")
    })
    .await
    .context("The deposit never became final")??;
    // Time for the sequencer to see the deposit final and produce on it.
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS).saturating_mul(2)).await;

    ensure!(
        account_balance(&ctx, recipient_id).await? == u128::from(amount),
        "The finalized deposit credited the recipient again"
    );

    Ok(())
}

// TODO(withdrawals): the vault program is deleted — deposits credit recipients
// directly now, so this helper has no target account; rework when withdrawals
// are re-enabled.
// async fn wait_for_vault_balance(
//     ctx: &TestContext,
//     vault_id: AccountId,
//     expected_balance: u128,
// ) -> anyhow::Result<()> {
//     let timeout = TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK
//         + Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS);
//     tokio::time::timeout(timeout, async {
//         loop {
//             let balance = account_balance(ctx, vault_id).await?;
//             if balance == expected_balance {
//                 return Ok(());
//             }
//             tokio::time::sleep(Duration::from_millis(500)).await;
//         }
//     })
//     .await
//     .with_context(|| {
//         format!("Timed out waiting for vault {vault_id} balance to reach {expected_balance}")
//     })?
// }

// TODO(withdrawals): predates the vault deletion — the deposit leg now credits
// the recipient directly and `Claim` no longer exists, so the claim step must
// go, not just be uncommented.
// /// Test deposit and withdraw round trip.
// ///
// /// Implemented as one test instead of two separate tests for deposit and withdraw, because the
// /// withdraw test depends on the deposit to set up the necessary state (funds in vault) for
// testing /// withdraw functionality.
// #[test]
// async fn bedrock_deposit_claim_and_withdraw_round_trip_succeeds() -> anyhow::Result<()> {
//     let mut ctx = TestContext::new().await?;

//     let bedrock_account_pk = "2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26";
//     let recipient_id = ctx.existing_public_accounts()[0];
//     let amount = 1_u64;
//     let vault_program_id = programs::vault_account_id();
//     let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id,
// recipient_id);

//     let vault_balance_before = account_balance(&ctx, recipient_vault_id).await?;
//     let recipient_balance_before = account_balance(&ctx, recipient_id).await?;

//     // Submit deposit to Bedrock
//     submit_bedrock_deposit(ctx.bedrock_addr(), bedrock_account_pk, recipient_id, amount)
//         .await
//         .context("Failed to submit Bedrock deposit for round-trip setup")?;

//     // Wait for vault to receive the deposit (minted from bridge to vault)
//     wait_for_vault_balance(
//         &ctx,
//         recipient_vault_id,
//         vault_balance_before + u128::from(amount),
//     )
//     .await?;

//     // Now claim funds from vault back to recipient
//     let nonces = ctx
//         .wallet()
//         .get_accounts_nonces(&[recipient_id])
//         .await
//         .context("Failed to get nonce for vault claim")?;

//     let signing_key = ctx
//         .wallet()
//         .storage()
//         .key_chain()
//         .pub_account_signing_key(recipient_id)
//         .with_context(|| format!("Missing signing key for account {recipient_id}"))?;

//     let claim_message = public_transaction::Message::try_new(
//         vault_program_id,
//         vec![recipient_id, recipient_vault_id],
//         nonces,
//         vault_core::Instruction::Claim {
//             amount: u128::from(amount),
//         },
//     )
//     .context("Failed to build vault claim message")?;

//     let claim_witness_set =
//         public_transaction::WitnessSet::for_message(&claim_message, &[signing_key]);
//     let claim_tx = LeeTransaction::Public(lee::PublicTransaction::new(
//         claim_message,
//         claim_witness_set,
//     ));

//     let claim_hash = ctx.sequencer_client().send_transaction(claim_tx).await?;

//     tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

//     let claim_on_chain = ctx.sequencer_client().get_transaction(claim_hash).await?;
//     let vault_balance_after_claim = account_balance(&ctx, recipient_vault_id).await?;
//     let recipient_balance_after_claim = account_balance(&ctx, recipient_id).await?;

//     assert!(
//         claim_on_chain.is_some(),
//         "Vault claim transaction must be included on-chain"
//     );
//     assert_eq!(
//         vault_balance_after_claim, vault_balance_before,
//         "Vault balance should return to initial state after claim"
//     );
//     assert_eq!(
//         recipient_balance_after_claim,
//         recipient_balance_before + u128::from(amount),
//         "Recipient balance should increase by claimed amount"
//     );

//     // The indexer must replay the deposit and claim blocks and reach the same
//     // state as the sequencer — including the bridge system account the deposit
//     // modifies, which is the case the hot fix unblocks.
//     wait_for_indexer_to_catch_up(&ctx).await?;
//     let bridge_account_id = system_accounts::bridge_account_id();
//     for account_id in [recipient_id, recipient_vault_id, bridge_account_id] {
//         let indexer_account = indexer_service_rpc::RpcClient::get_account(
//             // `deref` is needed for correct trait resolution
//             // of the async `get_account` method on `RpcClient`
//             ctx.indexer_client().deref(),
//             account_id.into(),
//         )
//         .await?;
//         let sequencer_account = get_account(&ctx, account_id).await?;
//         assert_eq!(
//             indexer_account,
//             sequencer_account.into(),
//             "Indexer and sequencer diverged for account {account_id} after deposit"
//         );
//     }

//     // Withdraw back to Bedrock and wait for finalized withdraw event.
//     let sender_id = recipient_id;

//     let observer = create_zone_indexer_observer(ctx.bedrock_addr())?;
//     let observe_fut =
//         wait_for_finalized_withdraw_op(&observer, ctx.bedrock_addr(), amount,
// bedrock_account_pk);

//     let withdraw_fut = execute_subcommand(
//         ctx.wallet_mut(),
//         Command::Bridge(BridgeSubcommand::Withdraw {
//             from: public_mention(sender_id),
//             amount,
//             bedrock_account_pk: bedrock_account_pk.to_owned(),
//         }),
//     );

//     let (observe_result, withdraw_result) = tokio::join!(observe_fut, withdraw_fut);

//     withdraw_result.context("Failed to execute wallet bridge withdraw command")?;

//     observe_result
//         .context("Failed while waiting for finalized withdraw event from zone indexer")?;

//     // Sleep to observe sequencer log about validated withdraw event
//     tokio::time::sleep(Duration::from_secs(1)).await;

//     Ok(())
// }

// fn create_zone_indexer_observer(
//     bedrock_addr: std::net::SocketAddr,
// ) -> anyhow::Result<ZoneIndexer<NodeHttpClient>> {
//     let bedrock_url = integration_tests::config::addr_to_url(
//         integration_tests::config::UrlProtocol::Http,
//         bedrock_addr,
//     )
//     .context("Failed to convert Bedrock addr to URL for zone indexer observer")?;

//     let node = NodeHttpClient::new(CommonHttpClient::new(None), bedrock_url);

//     Ok(ZoneIndexer::new(
//         integration_tests::config::bedrock_channel_id(),
//         node,
//     ))
// }

// /// Waits for a finalized withdraw that pays `expected_amount` to `receiver_pk`.
// ///
// /// A withdraw op releases channel-owned notes and carries nothing but their
// /// ids — the value and recipient live in the note itself. A released note keeps
// /// its id, value and public key, so the pairing is checked on the receiver's
// /// Bedrock wallet: one of the released notes must land there with the expected
// /// value.
// async fn wait_for_finalized_withdraw_op(
//     observer: &ZoneIndexer<NodeHttpClient>,
//     bedrock_addr: std::net::SocketAddr,
//     expected_amount: u64,
//     receiver_pk: &str,
// ) -> anyhow::Result<()> {
//     let timeout = TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK
//         + Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS);

//     tokio::time::timeout(timeout, async {
//         // The wallet can trail the channel event, so released notes accumulate
//         // across polls instead of being checked once when first observed.
//         let mut released_notes = HashSet::new();

//         loop {
//             let stream = observer
//                 .follow()
//                 .await
//                 .context("Failed to read zone indexer message batch")?;
//             let mut stream = std::pin::pin!(stream);

//             while let Some(message) = stream.next().await {
//                 log::info!("Observed zone message {message:?}");

//                 if let ZoneMessage::Withdraw(withdraw) = message {
//                     released_notes.extend(withdraw.inputs.iter().copied());
//                 }
//             }

//             if !released_notes.is_empty() {
//                 let balance = bedrock_wallet_balance(bedrock_addr, receiver_pk).await?;
//                 if released_notes
//                     .iter()
//                     .any(|note_id| balance.notes.get(note_id) == Some(&expected_amount))
//                 {
//                     return Ok(());
//                 }
//             }

//             tokio::time::sleep(Duration::from_millis(500)).await;
//         }
//     })
//     .await
//     .with_context(|| {
//         format!("Timed out waiting for finalized withdraw message with amount {expected_amount}")
//     })?
// }
