//! End-to-end demo of the sequencer self-join flow.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::{account_balance, get_account, new_account, public_mention, send};
use lee::{AccountId, PrivateKey, PublicKey, program::Program};
use log::info;
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, UnsecuredEd25519Key};
use sequencer_bedrock_actor::protocol::GetAccreditedKeys;
use sequencer_core::config::GenesisAction;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, SequencerPartialConfig, bedrock_channel_id},
    setup::{SequencerSetup, sequencer_client},
    spawn_channel_observer,
};
use tokio::test;
use wallet::AccountIdentity;

/// Bedrock signing key of the sequencer that stakes its way in.
const JOINER_SIGNING_KEY: [u8; 32] = [0x42; 32];

/// Short block cadence for the demo.
fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        priority_fee_percent: 150,
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
    let dust_sender_private_key = PrivateKey::new_os_random();
    let dust_sender_id =
        AccountId::from(&PublicKey::new_from_private_key(&dust_sender_private_key));

    // Comfortably above `system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE`, and
    // `u64` because genesis funds it through the bridge's `Deposit`.
    let funding_balance = u64::try_from(2 * system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE)
        .expect("funding balance fits u64");

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(fast_blocks())
                .with_genesis(vec![
                    GenesisAction::SupplyAccount {
                        account_id: funding_id,
                        balance: funding_balance,
                    },
                    GenesisAction::SupplyAccount {
                        account_id: dust_sender_id,
                        balance: funding_balance,
                    },
                ]),
        )
        .build()
        .await
        .context("Failed to build test context")?;

    // Import the funding key directly; it's not one of the wallet's default accounts.
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(funding_private_key);
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(dust_sender_private_key);

    info!("Waiting for the genesis supply to land on the funding account");
    poll_until("genesis supply to land", 30, || async {
        Ok(
            account_balance(&ctx, funding_id).await? == u128::from(funding_balance)
                && account_balance(&ctx, dust_sender_id).await? == u128::from(funding_balance),
        )
    })
    .await?;
    info!("Funded demo account {funding_id} with {funding_balance} native balance");

    let ownership_id = new_account(&mut ctx, false, None)
        .await
        .context("Failed to create a fresh stake ownership account")?;
    info!("Fresh stake ownership account: {ownership_id}");

    let funds_id = system_accounts::stake_funds_account_id(&ownership_id);

    // Anyone may credit the funds account before the stake lands: the stake must neither fail on
    // that balance nor count it.
    let dust = 1;
    send(
        &mut ctx,
        public_mention(dust_sender_id),
        public_mention(funds_id),
        dust,
    )
    .await
    .context("Failed to credit dust to the stake funds account")?;
    poll_until("the dust to reach the stake funds account", 30, || async {
        Ok(account_balance(&ctx, funds_id).await? == dust)
    })
    .await?;
    info!("An unrelated account credited {dust} to the stake funds account {funds_id}");

    let config_id = system_accounts::sequencer_stake_config_account_id();
    let stake_id = programs::sequencer_stake_account_id();
    // The proposal is read off the chain the stake is about to land on, the way `submit_stake`
    // builds it: it is checked against the account it describes.
    let has_record = !get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the stake ownership account")?
        .data
        .shard(stake_id)
        .is_empty();
    let stake_instruction_data =
        Program::serialize_instruction(sequencer_stake_core::Instruction::Stake {
            sequencer_key: demo_stake_key,
            amount: u128::from(funding_balance),
            has_record,
        })
        .context("Failed to serialize Stake instruction")?;

    info!(
        "Submitting Stake transaction for sequencer key {}",
        hex::encode(demo_sequencer_key.to_bytes())
    );
    ctx.wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::Public(funding_id).balance(),
                AccountIdentity::Public(ownership_id).select_program_shard(stake_id),
                AccountIdentity::PublicNoSign(funds_id).balance(),
                AccountIdentity::PublicNoSign(config_id).select_program_shard(stake_id),
            ],
            stake_instruction_data,
            stake_id,
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit Stake transaction: {err:?}"))?;

    info!("Waiting for the Stake transaction's block to land");
    poll_until("stake to take ownership", 30, || async {
        Ok(!get_account(&ctx, ownership_id)
            .await?
            .data
            .shard(stake_id)
            .is_empty())
    })
    .await?;

    let ownership_account = get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the stake ownership account")?;
    assert!(
        !ownership_account.data.shard(stake_id).is_empty(),
        "ownership account should now hold a sequencer_stake record"
    );
    let staked_balance = account_balance(&ctx, funds_id).await?;
    assert_eq!(
        staked_balance,
        u128::from(funding_balance) + dust,
        "the funds PDA should hold the staked balance on top of the dust"
    );
    assert_eq!(
        stake_entry(&ctx, config_id, demo_stake_key)
            .await?
            .map(|entry| entry.total_staked),
        Some(u128::from(funding_balance)),
        "the tracked stake is the requested amount, not the funds balance"
    );
    let record = sequencer_stake_core::StakeRecord::from_bytes(
        ownership_account.data.shard(stake_id).as_ref(),
    )
    .context("ownership account data did not decode as a StakeRecord")?;
    assert_eq!(record.sequencer_key, demo_stake_key);
    info!(
        "Ownership account confirmed: {funding_balance} staked for sequencer key {}",
        hex::encode(record.sequencer_key)
    );

    let observer = spawn_channel_observer(ctx.bedrock_addr(), bedrock_channel_id()).await?;

    // The committee-config update is a separate tx from the block's own
    // publish, so it may land a moment later — poll a few times before failing.
    let mut committee = None;
    for _ in 0..10 {
        let accredited = observer
            .ask(GetAccreditedKeys)
            .await
            .context("Failed to read the channel's accredited keys")?
            .context("Bedrock channel does not exist")?;
        if accredited.keys.contains(&demo_sequencer_key) {
            committee = Some(accredited);
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let committee = committee.context(
        "demo sequencer key should have been discovered and accredited after the Stake transaction",
    )?;
    info!(
        "Bedrock channel now accredits {} key(s), including the demo sequencer key — self-join complete",
        committee.keys.len()
    );

    // Only now start a node behind the key, against a channel that already has a chain.
    let (joiner, _joiner_home) = SequencerSetup::new(fast_blocks(), ctx.bedrock_addr())
        .with_channel_id(bedrock_channel_id())
        .with_bedrock_signing_key(UnsecuredEd25519Key::from_bytes(&JOINER_SIGNING_KEY))
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
        let observer = &observer;
        let ctx = &ctx;
        move || async move {
            let Some(accredited) = observer.ask(GetAccreditedKeys).await? else {
                return Ok(false);
            };
            Ok(accredited.whose_turn() == Some(demo_sequencer_key)
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
    // Unstake recipient is freely chosen during the request.
    let destination_id = funding_id;

    let requested_at = ctx
        .sequencer_client()
        .get_last_block_id()
        .await?
        .saturating_add(sequencer_stake_core::UNSTAKE_REQUEST_WINDOW);
    let unstake_request_data =
        Program::serialize_instruction(sequencer_stake_core::Instruction::UnstakeRequest {
            sequencer_key: demo_stake_key,
            amount: u128::from(funding_balance),
            destination: destination_id,
            requested_at,
        })
        .context("Failed to serialize UnstakeRequest instruction")?;
    ctx.wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::Public(ownership_id).select_program_shard(stake_id),
                AccountIdentity::PublicNoSign(config_id).select_program_shard(stake_id),
            ],
            unstake_request_data,
            stake_id,
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
        let accredited = observer
            .ask(GetAccreditedKeys)
            .await
            .context("Failed to read the channel's accredited keys")?
            .context("Bedrock channel does not exist")?;
        if !accredited.keys.contains(&demo_sequencer_key) {
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
        "FinalizeUnstake to release the stake from the funds account",
        90,
        || async { Ok(account_balance(&ctx, funds_id).await? == dust) },
    )
    .await?;

    let drained_ownership_account = get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the ownership account after the release")?;
    assert_eq!(
        drained_ownership_account.data.native_balance().unwrap(),
        0,
        "the ownership account never custodies the stake"
    );
    let drained_record = sequencer_stake_core::StakeRecord::from_bytes(
        drained_ownership_account.data.shard(stake_id).as_ref(),
    )
    .context("drained ownership account data did not decode as a StakeRecord")?;
    assert!(
        drained_record.pending_unstake.is_none(),
        "pending unstake should be cleared"
    );

    let destination_balance = account_balance(&ctx, destination_id).await?;
    assert_eq!(
        destination_balance,
        u128::from(funding_balance),
        "destination should receive the released stake"
    );

    // Nothing is at stake for this key any more: a fully released stake has
    // its config entry removed outright.
    assert!(
        stake_entry(&ctx, config_id, demo_stake_key)
            .await?
            .is_none(),
        "the config entry should be gone once the stake is fully released"
    );
    info!(
        "FinalizeUnstake auto-included: {funding_balance} released to {destination_id}, nothing left at stake"
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
    let config = sequencer_stake_core::SequencerStakeConfig::from_bytes(
        config_account
            .data
            .shard(programs::sequencer_stake_account_id())
            .as_ref(),
    )
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
