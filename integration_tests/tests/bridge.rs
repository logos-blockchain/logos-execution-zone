#![expect(
    clippy::tests_outside_test_module,
    clippy::arithmetic_side_effects,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Context as _;
use borsh::BorshSerialize;
use common::transaction::LeeTransaction;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext};
use lee::{
    AccountId, execute_and_prove, privacy_preserving_transaction, program::Program,
    public_transaction,
};
use lee_core::{InputAccountIdentity, account::AccountWithMetadata};
use log::info;
use logos_blockchain_core::mantle::{Value, ledger::Inputs, ops::channel::deposit::DepositOp};
use logos_blockchain_http_api_common::bodies::{
    channel::ChannelDepositRequestBody,
    wallet::{
        balance::WalletBalanceResponseBody,
        transfer_funds::{WalletTransferFundsRequestBody, WalletTransferFundsResponseBody},
    },
};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;

const TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK: Duration = Duration::from_mins(2);

#[test]
async fn public_bridge_deposit_invocation_is_dropped() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let bridge_account_id = lee::system_bridge_account_id();
    let vault_program_id = Program::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient_id);

    let message = public_transaction::Message::try_new(
        Program::bridge().id(),
        vec![bridge_account_id, recipient_vault_id],
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
        "Direct public bridge::Deposit invocation should be rejected"
    );

    Ok(())
}

#[test]
async fn private_bridge_deposit_invocation_is_dropped() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let bridge_account_id = lee::system_bridge_account_id();
    let vault_program_id = Program::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient_id);

    // Get pre-state of bridge and vault accounts
    let bridge_pre = AccountWithMetadata::new(
        ctx.sequencer_client()
            .get_account(bridge_account_id)
            .await?,
        false,
        bridge_account_id,
    );
    let vault_pre = AccountWithMetadata::new(
        ctx.sequencer_client()
            .get_account(recipient_vault_id)
            .await?,
        false,
        recipient_vault_id,
    );

    // Create program with dependencies
    let program_with_deps =
        lee::privacy_preserving_transaction::circuit::ProgramWithDependencies::new(
            Program::bridge(),
            [
                (vault_program_id, Program::vault()),
                (
                    Program::authenticated_transfer_program().id(),
                    Program::authenticated_transfer_program(),
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
        vec![bridge_pre.clone(), vault_pre.clone()],
        instruction,
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program_with_deps,
    )
    .context("Failed to execute/prove bridge deposit")?;

    // Create privacy-preserving transaction from circuit output
    let message = privacy_preserving_transaction::Message::try_from_circuit_output(
        vec![bridge_account_id, recipient_vault_id],
        vec![bridge_pre.account.nonce, vault_pre.account.nonce],
        vec![],
        output,
    )
    .context("Failed to build privacy-preserving bridge deposit message")?;

    let witness_set = privacy_preserving_transaction::WitnessSet::for_message(&message, proof, &[]);
    let attack_tx = LeeTransaction::PrivacyPreserving(lee::PrivacyPreservingTransaction::new(
        message,
        witness_set,
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
        "Privacy-preserving bridge::Deposit invocation should be rejected"
    );

    Ok(())
}

async fn submit_bedrock_deposit(
    bedrock_addr: std::net::SocketAddr,
    recipient_id: AccountId,
    amount: u128,
) -> anyhow::Result<()> {
    #[derive(BorshSerialize)]
    struct DepositMetadata {
        recipient_id: AccountId,
    }

    // Encode deposit metadata
    let metadata = borsh::to_vec(&DepositMetadata { recipient_id })
        .context("Failed to encode deposit metadata")?
        .try_into()
        .context("Encoded metadata is too big")?;

    let funding_key = "2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26";

    let amount: Value = amount
        .try_into()
        .context("Deposit amount does not fit Bedrock Value type")?;
    let channel_id = integration_tests::config::bedrock_channel_id();
    let client = reqwest::Client::new();

    let query_balance = || async {
        let balance_response = client
            .get(format!(
                "http://{bedrock_addr}/wallet/{funding_key}/balance"
            ))
            .send()
            .await
            .context("Failed to query Bedrock wallet balance")?;

        let balance_response = check_response_success(balance_response).await?;

        balance_response
            .json::<WalletBalanceResponseBody>()
            .await
            .context("Failed to decode Bedrock balance response")
    };

    let mut balance = query_balance().await?;

    info!(
        "Queried Bedrock balance for key {funding_key}: {:?}",
        balance.balance
    );

    if balance.balance < amount {
        anyhow::bail!(
            "Bedrock wallet with key {funding_key} has insufficient balance {:?} for deposit amount {:?}",
            balance.balance,
            amount
        );
    }

    let mut selected_note_id = balance
        .notes
        .iter()
        .find_map(|(note_id, value)| (*value == amount).then_some(*note_id));

    if selected_note_id.is_none() {
        let transfer_body = WalletTransferFundsRequestBody {
            tip: None,
            change_public_key: balance.address,
            funding_public_keys: vec![balance.address],
            recipient_public_key: balance.address,
            amount,
        };

        let transfer_response = client
            .post(format!(
                "http://{bedrock_addr}/wallet/transactions/transfer-funds"
            ))
            .json(&transfer_body)
            .send()
            .await
            .context("Failed to submit Bedrock transfer-funds request")?;
        let transfer_response = check_response_success(transfer_response).await?;

        let transfer: WalletTransferFundsResponseBody = transfer_response
            .json()
            .await
            .context("Failed to decode Bedrock transfer-funds response")?;

        info!(
            "Submitted transfer-funds to create exact deposit note, tx hash {:?}",
            transfer.hash
        );

        let mut found_note = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            balance = query_balance().await?;
            found_note = balance
                .notes
                .iter()
                .find_map(|(note_id, value)| (*value == amount).then_some(*note_id));
            if found_note.is_some() {
                break;
            }
        }

        selected_note_id = found_note;
    }

    let Some(selected_note_id) = selected_note_id else {
        anyhow::bail!(
            "Failed to locate exact-value note {amount:?} for Bedrock deposit; available notes: {:?}",
            balance.notes,
        );
    };

    let body = ChannelDepositRequestBody {
        tip: None,
        deposit: DepositOp {
            channel_id,
            inputs: Inputs::new(selected_note_id),
            metadata,
        },
        change_public_key: balance.address,
        funding_public_keys: vec![balance.address],
        max_tx_fee: 1_000_u64.into(),
    };

    let response = client
        .post(format!("http://{bedrock_addr}/channel/deposit"))
        .json(&body)
        .send()
        .await
        .context("Failed to submit Bedrock deposit request")?;
    let response = check_response_success(response).await?;

    let body_text = response
        .text()
        .await
        .unwrap_or_else(|_| "<failed to decode>".to_owned());
    info!(
        "Successfully submitted Bedrock deposit request for recipient {recipient_id} and amount {amount}, response body: {body_text}",
    );

    Ok(())
}

async fn check_response_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        anyhow::bail!("Request failed with status {status} and body {body_text}");
    }
}

async fn wait_for_vault_balance(
    ctx: &TestContext,
    vault_id: AccountId,
    expected_balance: u128,
) -> anyhow::Result<()> {
    let timeout = TIME_TO_FINALIZE_DEPOSIT_EVENT_ON_BEDROCK
        + Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS);
    tokio::time::timeout(timeout, async {
        loop {
            let balance = ctx.sequencer_client().get_account_balance(vault_id).await?;
            if balance == expected_balance {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .with_context(|| {
        format!("Timed out waiting for vault {vault_id} balance to reach {expected_balance}")
    })?
}

#[test]
async fn bedrock_deposit_mints_to_vault_then_claim_succeeds() -> anyhow::Result<()> {
    let ctx = TestContext::new().await?;

    let recipient_id = ctx.existing_public_accounts()[0];
    let vault_program_id = Program::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient_id);

    let vault_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;
    let recipient_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient_id)
        .await?;

    // Submit deposit to Bedrock
    submit_bedrock_deposit(ctx.bedrock_addr(), recipient_id, 1).await?;

    // Wait for vault to receive the deposit (minted from bridge to vault)
    wait_for_vault_balance(&ctx, recipient_vault_id, vault_balance_before + 1).await?;

    // Now claim funds from vault back to recipient
    let nonces = ctx
        .wallet()
        .get_accounts_nonces(vec![recipient_id])
        .await
        .context("Failed to get nonce for vault claim")?;

    let signing_key = ctx
        .wallet()
        .storage()
        .key_chain()
        .pub_account_signing_key(recipient_id)
        .with_context(|| format!("Missing signing key for account {recipient_id}"))?;

    let claim_message = public_transaction::Message::try_new(
        vault_program_id,
        vec![recipient_id, recipient_vault_id],
        nonces,
        vault_core::Instruction::Claim { amount: 1 },
    )
    .context("Failed to build vault claim message")?;

    let claim_witness_set =
        public_transaction::WitnessSet::for_message(&claim_message, &[signing_key]);
    let claim_tx = LeeTransaction::Public(lee::PublicTransaction::new(
        claim_message,
        claim_witness_set,
    ));

    let claim_hash = ctx.sequencer_client().send_transaction(claim_tx).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let claim_on_chain = ctx.sequencer_client().get_transaction(claim_hash).await?;
    let vault_balance_after_claim = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;
    let recipient_balance_after_claim = ctx
        .sequencer_client()
        .get_account_balance(recipient_id)
        .await?;

    assert!(
        claim_on_chain.is_some(),
        "Vault claim transaction must be included on-chain"
    );
    assert_eq!(
        vault_balance_after_claim, vault_balance_before,
        "Vault balance should return to initial state after claim"
    );
    assert_eq!(
        recipient_balance_after_claim,
        recipient_balance_before + 1,
        "Recipient balance should increase by claimed amount"
    );

    Ok(())
}
