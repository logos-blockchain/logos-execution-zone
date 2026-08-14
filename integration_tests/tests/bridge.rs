#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Context as _;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, account_balance, get_account,
};
use lee::{
    execute_and_prove, privacy_preserving_transaction, program::Program, public_transaction,
};
use lee_core::{InputAccountIdentity, account::AccountWithMetadata};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;

// const TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK: Duration = Duration::from_mins(2);

#[test]
async fn public_bridge_deposit_invocation_is_dropped() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let bridge_account_id = system_accounts::bridge_account_id();
    let vault_program_id = programs::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient_id);
    let receipt_id = bridge_core::deposit_receipt_account_id(programs::bridge().id(), [0_u8; 32]);

    let message = public_transaction::Message::try_new(
        programs::bridge().id().into(),
        vec![bridge_account_id, recipient_vault_id, receipt_id],
        vec![],
        bridge_core::Instruction::Deposit {
            l1_deposit_op_id: [0_u8; 32],
            vault_program_id,
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
    let vault_balance_before = account_balance(&ctx, recipient_vault_id).await?;

    let tx_hash = ctx.sequencer_client().send_transaction(attack_tx).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let bridge_balance_after = account_balance(&ctx, bridge_account_id).await?;
    let vault_balance_after = account_balance(&ctx, recipient_vault_id).await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(bridge_balance_after, bridge_balance_before);
    assert_eq!(vault_balance_after, vault_balance_before);
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
    let vault_program_id = programs::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient_id);
    let receipt_id = bridge_core::deposit_receipt_account_id(programs::bridge().id(), [0_u8; 32]);

    let message = public_transaction::Message::try_new(
        programs::bridge().id().into(),
        vec![bridge_account_id, recipient_vault_id, receipt_id],
        vec![],
        bridge_core::Instruction::Deposit {
            l1_deposit_op_id: [0_u8; 32],
            vault_program_id,
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
    let vault_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;

    let tx_hash = ctx.sequencer_client().send_transaction(attack_tx).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let bridge_balance_after = ctx
        .sequencer_client()
        .get_account_balance(bridge_account_id)
        .await?;
    let vault_balance_after = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(bridge_balance_after, bridge_balance_before);
    assert_eq!(vault_balance_after, vault_balance_before);
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
    let vault_program_id = programs::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient_id);
    let receipt_id = bridge_core::deposit_receipt_account_id(programs::bridge().id(), [0_u8; 32]);

    // Get pre-state of bridge and vault accounts; the receipt is unminted (a
    // default account), so the program would create it on a first mint.
    let bridge_pre = AccountWithMetadata::new(
        get_account(&ctx, bridge_account_id).await?,
        false,
        bridge_account_id,
    );
    let vault_pre = AccountWithMetadata::new(
        get_account(&ctx, recipient_vault_id).await?,
        false,
        recipient_vault_id,
    );
    let receipt_pre =
        AccountWithMetadata::new(lee_core::account::Account::default(), false, receipt_id);

    // Create program with dependencies
    let program_with_deps =
        lee::privacy_preserving_transaction::circuit::ProgramWithDependencies::new(
            programs::bridge(),
            [
                (vault_program_id, programs::vault()),
                (
                    programs::authenticated_transfer().id(),
                    programs::authenticated_transfer(),
                ),
            ]
            .into(),
        );

    // Serialize the bridge deposit instruction
    let instruction = Program::serialize_instruction(bridge_core::Instruction::Deposit {
        l1_deposit_op_id: [0_u8; 32],
        vault_program_id,
        recipient_id,
        amount: 1,
    })
    .context("Failed to serialize bridge deposit instruction")?;

    // Execute and prove the bridge deposit
    let (output, proof) = execute_and_prove(
        vec![bridge_pre.clone(), vault_pre.clone(), receipt_pre.clone()],
        instruction,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
        ],
        &program_with_deps,
    )
    .context("Failed to execute/prove bridge deposit")?;

    // Create privacy-preserving transaction from circuit output
    let message = privacy_preserving_transaction::Message::from_circuit_output(
        vec![
            bridge_pre.account.nonce,
            vault_pre.account.nonce,
            receipt_pre.account.nonce,
        ],
        output,
    );

    let witness_set = privacy_preserving_transaction::WitnessSet::for_message(&message, proof, &[]);
    let attack_tx = LeeTransaction::PrivacyPreserving(lee::PrivacyPreservingTransaction::new(
        message,
        witness_set,
    ));

    let bridge_balance_before = account_balance(&ctx, bridge_account_id).await?;
    let vault_balance_before = account_balance(&ctx, recipient_vault_id).await?;

    let tx_hash = ctx.sequencer_client().send_transaction(attack_tx).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let bridge_balance_after = account_balance(&ctx, bridge_account_id).await?;
    let vault_balance_after = account_balance(&ctx, recipient_vault_id).await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(bridge_balance_after, bridge_balance_before);
    assert_eq!(vault_balance_after, vault_balance_before);
    assert!(
        tx_on_chain.is_none(),
        "Privacy-preserving bridge::Deposit invocation should be rejected"
    );

    Ok(())
}

// async fn submit_bedrock_deposit(
//     bedrock_addr: std::net::SocketAddr,
//     bedrock_account_pk: &str,
//     recipient_id: AccountId,
//     amount: u64,
// ) -> anyhow::Result<()> {
//     #[derive(BorshSerialize)]
//     struct DepositMetadata {
//         recipient_id: AccountId,
//     }

//     // Encode deposit metadata
//     let metadata = borsh::to_vec(&DepositMetadata { recipient_id })
//         .context("Failed to encode deposit metadata")?
//         .try_into()
//         .context("Encoded metadata is too big")?;

//     let channel_id = integration_tests::config::bedrock_channel_id();
//     let client = reqwest::Client::new();

//     let mut balance = bedrock_wallet_balance(bedrock_addr, bedrock_account_pk).await?;

//     log::info!(
//         "Queried Bedrock balance for key {bedrock_account_pk}: {:?}",
//         balance.balance
//     );

//     if balance.balance < amount {
//         anyhow::bail!(
//             "Bedrock wallet with key {bedrock_account_pk} has insufficient balance {:?} for
// deposit amount {:?}",             balance.balance,
//             amount
//         );
//     }

//     let mut selected_note_id = balance
//         .notes
//         .iter()
//         .find_map(|(note_id, value)| (*value == amount).then_some(*note_id));

//     if selected_note_id.is_none() {
//         let transfer_body = WalletTransferFundsRequestBody {
//             tip: None,
//             change_public_key: balance.address,
//             funding_public_keys: vec![balance.address],
//             recipient_public_key: balance.address,
//             amount,
//         };

//         let transfer_response = client
//             .post(format!(
//                 "http://{bedrock_addr}/wallet/transactions/transfer-funds"
//             ))
//             .json(&transfer_body)
//             .send()
//             .await
//             .context("Failed to submit Bedrock transfer-funds request")?;
//         let transfer_response = check_response_success(transfer_response).await?;

//         let transfer: WalletTransferFundsResponseBody = transfer_response
//             .json()
//             .await
//             .context("Failed to decode Bedrock transfer-funds response")?;

//         log::info!(
//             "Submitted transfer-funds to create exact deposit note, tx hash {:?}",
//             transfer.hash
//         );

//         let mut found_note = None;
//         for _ in 0..20 {
//             tokio::time::sleep(Duration::from_millis(500)).await;
//             balance = bedrock_wallet_balance(bedrock_addr, bedrock_account_pk).await?;
//             found_note = balance
//                 .notes
//                 .iter()
//                 .find_map(|(note_id, value)| (*value == amount).then_some(*note_id));
//             if found_note.is_some() {
//                 break;
//             }
//         }

//         selected_note_id = found_note;
//     }

//     let Some(selected_note_id) = selected_note_id else {
//         anyhow::bail!(
//             "Failed to locate exact-value note {amount:?} for Bedrock deposit; available notes:
// {:?}",             balance.notes,
//         );
//     };

//     let body = ChannelDepositRequestBody {
//         tip: None,
//         deposit: DepositOp {
//             channel_id,
//             inputs: Inputs::new(selected_note_id),
//             metadata,
//         },
//         change_public_key: balance.address,
//         funding_public_keys: vec![balance.address],
//         max_tx_fee: u64::MAX.into(),
//     };

//     let response = client
//         .post(format!("http://{bedrock_addr}/channel/deposit"))
//         .json(&body)
//         .send()
//         .await
//         .context("Failed to submit Bedrock deposit request")?;
//     let response = check_response_success(response).await?;

//     let body_text = response
//         .text()
//         .await
//         .unwrap_or_else(|_| "<failed to decode>".to_owned());
//     log::info!(
//         "Successfully submitted Bedrock deposit request for recipient {recipient_id} and amount
// {amount}, response body: {body_text}",     );

//     Ok(())
// }

// /// The Bedrock wallet state of `bedrock_account_pk`: its total balance and the
// /// notes it owns, keyed by note id.
// async fn bedrock_wallet_balance(
//     bedrock_addr: std::net::SocketAddr,
//     bedrock_account_pk: &str,
// ) -> anyhow::Result<WalletBalanceResponseBody> {
//     let response = reqwest::Client::new()
//         .get(format!(
//             "http://{bedrock_addr}/wallet/{bedrock_account_pk}/balance"
//         ))
//         .send()
//         .await
//         .context("Failed to query Bedrock wallet balance")?;

//     check_response_success(response)
//         .await?
//         .json::<WalletBalanceResponseBody>()
//         .await
//         .context("Failed to decode Bedrock balance response")
// }

// async fn check_response_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response>
// {     if response.status().is_success() {
//         Ok(response)
//     } else {
//         let status = response.status();
//         let body_text = response.text().await.unwrap_or_default();
//         anyhow::bail!("Request failed with status {status} and body {body_text}");
//     }
// }

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
//     let vault_program_id = programs::vault().id();
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
