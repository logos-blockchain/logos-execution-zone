//! End-to-end demo of the sequencer self-join flow.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::{account_balance, get_account, new_account};
use lee::{AccountId, PrivateKey, PublicKey, program::Program};
use log::info;
use logos_blockchain_core::mantle::ops::channel::Ed25519PublicKey;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
};
use sequencer_core::config::GenesisAction;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{
        MultiNodeTestContextConfig, SequencerPartialConfig, UrlProtocol, addr_to_url,
        bedrock_channel_id,
    },
    setup::{SequencerSetup, sequencer_client},
};
use tokio::test;
use wallet::AccountIdentity;

/// Comfortably above `system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE`.
const FUNDING_BALANCE: u128 = 2 * system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

/// Bedrock signing key of the sequencer that stakes its way in.
const JOINER_SIGNING_KEY: [u8; 32] = [0x42; 32];

/// Short block cadence for the demo.
fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        ..SequencerPartialConfig::default()
    }
}

#[test]
async fn stake_transaction_joins_the_bedrock_committee() -> Result<()> {
    let demo_sequencer_key = Ed25519Key::from_bytes(&JOINER_SIGNING_KEY).public_key();
    let demo_stake_key = sequencer_stake_core::SequencerKey::new(demo_sequencer_key.to_bytes())
        .expect("a Bedrock key is a valid Ed25519 public key");

    let funding_private_key = PrivateKey::new_os_random();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_private_key));

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(fast_blocks())
                .with_genesis(vec![GenesisAction::SupplyAccount {
                    account_id: funding_id,
                    balance: FUNDING_BALANCE,
                }]),
        )
        .build()
        .await
        .context("Failed to build test context")?;

    // Import the funding key directly; it's not one of the wallet's default accounts.
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(funding_private_key);

    // Claim the genesis supply out of its vault.
    let owner_vault_id =
        vault_core::compute_vault_account_id(programs::vault().deployed_account_id(), funding_id);
    let claim_instruction_data = Program::serialize_instruction(vault_core::Instruction::Claim {
        amount: FUNDING_BALANCE,
    })
    .context("Failed to serialize vault Claim instruction")?;
    ctx.wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::Public(funding_id),
                AccountIdentity::PublicNoSign(owner_vault_id),
            ],
            claim_instruction_data,
            programs::vault().id(),
        )
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to claim the demo funding account from its genesis vault: {err:?}"
            )
        })?;
    info!("Waiting for the vault-claim transaction's block to land");
    poll_until("vault claim to land", 30, || async {
        Ok(account_balance(&ctx, funding_id).await? == FUNDING_BALANCE)
    })
    .await?;
    info!("Funded demo account {funding_id} with {FUNDING_BALANCE} native balance");

    let ownership_id = new_account(&mut ctx, false, None)
        .await
        .context("Failed to create a fresh stake ownership account")?;
    info!("Fresh stake ownership account: {ownership_id}");

    let mover_instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: FUNDING_BALANCE,
        })
        .context("Failed to serialize mover instruction")?;
    let stake_instruction_data =
        Program::serialize_instruction(sequencer_stake_core::Instruction::Stake {
            sequencer_key: demo_stake_key,
            amount: FUNDING_BALANCE,
            mover_account_id: program_loader_core::immutable_deploy_account_id(
                programs::authenticated_transfer().id(),
            ),
            mover_instruction_data,
        })
        .context("Failed to serialize Stake instruction")?;

    info!(
        "Submitting Stake transaction for sequencer key {}",
        hex::encode(demo_sequencer_key.to_bytes())
    );
    let config_id = system_accounts::sequencer_stake_config_account_id();
    ctx.wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::Public(funding_id),
                AccountIdentity::Public(ownership_id),
                AccountIdentity::PublicNoSign(config_id),
            ],
            stake_instruction_data,
            programs::sequencer_stake().id(),
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit Stake transaction: {err:?}"))?;

    info!("Waiting for the Stake transaction's block to land");
    poll_until("stake to take ownership", 30, || async {
        Ok(get_account(&ctx, ownership_id).await?.program_owner
            == programs::sequencer_stake().id().into())
    })
    .await?;

    let ownership_account = get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the stake ownership account")?;
    assert_eq!(
        ownership_account.program_owner,
        programs::sequencer_stake().id().into(),
        "ownership account should now be owned by sequencer_stake"
    );
    assert_eq!(
        ownership_account.balance, FUNDING_BALANCE,
        "ownership account should hold the staked balance"
    );
    let record = sequencer_stake_core::StakeRecord::from_bytes(ownership_account.data.as_ref())
        .context("ownership account data did not decode as a StakeRecord")?;
    assert_eq!(record.sequencer_key, demo_stake_key);
    info!(
        "Ownership account confirmed: {} staked for sequencer key {}",
        ownership_account.balance,
        hex::encode(record.sequencer_key)
    );

    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.bedrock_addr())
        .context("Failed to build the Bedrock node URL")?;
    let node = NodeHttpClient::new(CommonHttpClient::new(None), bedrock_url);

    // The committee-config update is a separate tx from the block's own
    // publish, so it may land a moment later — poll a few times before failing.
    let mut channel_state = None;
    for _ in 0..10 {
        let state = node
            .channel_state(bedrock_channel_id())
            .await
            .context("Failed to read Bedrock channel state")?
            .context("Bedrock channel does not exist")?;
        if state
            .accredited_keys
            .iter()
            .any(|key: &Ed25519PublicKey| *key == demo_sequencer_key)
        {
            channel_state = Some(state);
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let channel_state = channel_state.context(
        "demo sequencer key should have been discovered and accredited after the Stake transaction",
    )?;
    info!(
        "Bedrock channel now accredits {} key(s), including the demo sequencer key — self-join complete",
        channel_state.accredited_keys.len()
    );

    // Only now start a node behind the key, against a channel that already has a chain.
    let (joiner, _joiner_home) = SequencerSetup::new(fast_blocks(), ctx.bedrock_addr())
        .with_channel_id(bedrock_channel_id())
        .with_bedrock_signing_key(JOINER_SIGNING_KEY)
        .joining_existing_channel()
        .setup()
        .await
        .context("Failed to start the joining sequencer")?;
    let joiner_client = sequencer_client(joiner.addr())?;

    let joined_at = ctx.sequencer_client().get_last_block_id().await?;
    poll_until("the joining sequencer to sync the existing chain", 120, {
        let joiner_client = &joiner_client;
        move || async move { Ok(joiner_client.get_last_block_id().await? >= joined_at) }
    })
    .await?;
    info!("Joining sequencer synced to block {joined_at}");

    // A tip past `joined_at` under the demo key is a block this node built.
    poll_until("the joining sequencer to build a block on its turn", 180, {
        let node = &node;
        let ctx = &ctx;
        move || async move {
            let Some(state) = node.channel_state(bedrock_channel_id()).await? else {
                return Ok(false);
            };
            let turn = state
                .accredited_keys
                .get(usize::from(state.tip_sequencer))
                .copied();
            Ok(turn == Some(demo_sequencer_key)
                && ctx.sequencer_client().get_last_block_id().await? > joined_at)
        }
    })
    .await?;
    info!("Joining sequencer produced a block on its round-robin turn");

    // Both nodes agree, block for block, over everything they share.
    let leader_client = ctx.sequencer_client();
    let common = leader_client
        .get_last_block_id()
        .await?
        .min(joiner_client.get_last_block_id().await?);
    for id in 1..=common {
        let leader_block = leader_client
            .get_block(id)
            .await?
            .with_context(|| format!("Leader is missing block {id}"))?;
        let joiner_block = joiner_client
            .get_block(id)
            .await?
            .with_context(|| format!("Joining sequencer is missing block {id}"))?;
        anyhow::ensure!(
            leader_block.header.hash == joiner_block.header.hash,
            "Chain divergence at block {id}: leader {:?} vs joiner {:?}",
            leader_block.header.hash,
            joiner_block.header.hash
        );
    }
    info!("Leader and joining sequencer agree on all {common} shared blocks");

    // Exit flow: full UnstakeRequest, wait for the committee removal to land on
    // Bedrock, then check the sequencer's own FinalizeUnstake releases the stake.
    //
    // FinalizeUnstake is unsigned/permissionless, so it can't claim a fresh
    // destination account (that needs the owner's own signature, same as
    // authenticated_transfer's Transfer). Reuse funding_id: already
    // authenticated_transfer-owned, drained to 0 by the Stake above.
    let destination_id = funding_id;

    let unstake_request_data =
        Program::serialize_instruction(sequencer_stake_core::Instruction::UnstakeRequest {
            amount: FUNDING_BALANCE,
            destination: destination_id,
        })
        .context("Failed to serialize UnstakeRequest instruction")?;
    ctx.wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::Public(ownership_id),
                AccountIdentity::PublicNoSign(config_id),
            ],
            unstake_request_data,
            programs::sequencer_stake().id(),
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit UnstakeRequest transaction: {err:?}"))?;
    info!("Submitted full UnstakeRequest for the demo sequencer key");

    // A full drain crosses below the minimum, so discovery removes the key.
    // Wide window: the removal has to wait for this sequencer to regain its
    // round-robin turn (posting_timeframe/posting_timeout reclaim), on top of
    // normal Bedrock confirmation latency.
    let mut removed = false;
    for _ in 0..30 {
        let state = node
            .channel_state(bedrock_channel_id())
            .await
            .context("Failed to read Bedrock channel state")?
            .context("Bedrock channel does not exist")?;
        if !state
            .accredited_keys
            .iter()
            .any(|key: &Ed25519PublicKey| *key == demo_sequencer_key)
        {
            removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    anyhow::ensure!(
        removed,
        "demo sequencer key should have been removed after the full UnstakeRequest"
    );
    info!("Demo sequencer key removed from the Bedrock committee");

    // Once removed, the sequencer injects FinalizeUnstake itself; this test
    // never submits one.
    poll_until(
        "FinalizeUnstake to drain the ownership account",
        90,
        || async { Ok(get_account(&ctx, ownership_id).await?.balance == 0) },
    )
    .await?;

    let drained_ownership_account = get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the drained ownership account")?;
    assert_eq!(
        drained_ownership_account.balance, 0,
        "ownership account should be fully drained"
    );
    let drained_record =
        sequencer_stake_core::StakeRecord::from_bytes(drained_ownership_account.data.as_ref())
            .context("drained ownership account data did not decode as a StakeRecord")?;
    assert!(
        drained_record.pending_unstake.is_none(),
        "pending unstake should be cleared"
    );

    let destination_balance = account_balance(&ctx, destination_id).await?;
    assert_eq!(
        destination_balance, FUNDING_BALANCE,
        "destination should receive the released stake"
    );

    // Nothing is at stake for this key any more: a fully drained account has
    // its config entry removed outright.
    assert!(
        stake_entry(&ctx, config_id, demo_stake_key)
            .await?
            .is_none(),
        "the config entry should be gone once the stake is fully released"
    );
    info!(
        "FinalizeUnstake auto-included: {FUNDING_BALANCE} released to {destination_id}, nothing left at stake"
    );

    Ok(())
}

/// The `sequencer_stake` config entry for `sequencer_key`, or `None` if the key
/// has nothing at stake.
async fn stake_entry(
    ctx: &TestContext,
    config_id: AccountId,
    sequencer_key: sequencer_stake_core::SequencerKey,
) -> Result<Option<sequencer_stake_core::SequencerEntry>> {
    let config_account = get_account(ctx, config_id)
        .await
        .context("Failed to read the sequencer_stake config account")?;
    let config =
        sequencer_stake_core::SequencerStakeConfig::from_bytes(config_account.data.as_ref())
            .context("config account data did not decode as a SequencerStakeConfig")?;
    Ok(config.entries.get(&sequencer_key).copied())
}

/// Polls `check` once a second, up to `max_attempts` times, replacing fixed
/// block-wait sleeps: the accelerated devnet crosses an epoch boundary every
/// ~100 slots, so every second of wall-clock spent sleeping increases the
/// chance of straddling one.
async fn poll_until<F, Fut>(what: &str, max_attempts: u32, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    for _ in 0..max_attempts {
        if check().await.unwrap_or(false) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("timed out waiting for {what}")
}
