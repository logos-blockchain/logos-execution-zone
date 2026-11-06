//! End-to-end demo of the sequencer self-join flow.

#![expect(
    clippy::tests_outside_test_module,
    clippy::arithmetic_side_effects,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::{
    HashType,
    block::Block,
    transaction::{FeePayee, LeeTransaction, fee_invocation_payee},
};
use integration_tests::{account_balance, get_account, new_account, wait_for_same_chain};
use lee::{AccountId, PrivateKey, PublicAccountEvidence, PublicKey, program::Program};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, UnsecuredEd25519Key};
use sequencer_bedrock_actor::protocol::GetAccreditedKeys;
use sequencer_core::config::{DepositRecipient, GenesisAction};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, SequencerPartialConfig, bedrock_channel_id},
    setup::{SequencerSetup, sequencer_client},
    spawn_channel_observer,
};
use tokio::test;
use tracing::info;
use wallet::{AccountIdentity, program_facades::sequencer_stake::SequencerStake};

/// Channel signing key of the sequencer that stakes its way in.
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
        .expect("a channel signing public key is a valid Ed25519 public key");

    let funding_private_key = PrivateKey::new_os_random();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_private_key));

    // Comfortably above `system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE`, and
    // `u64` because genesis funds it through the bridge's `Deposit`.
    let funding_balance = u64::try_from(2 * system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE)
        .expect("funding balance fits u64");

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(fast_blocks())
                .with_genesis(vec![GenesisAction::SupplyAccount {
                    recipient: DepositRecipient::Identified(PublicAccountEvidence::Key(
                        PublicKey::new_from_private_key(&funding_private_key),
                    )),
                    balance: funding_balance,
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

    info!("Waiting for the genesis supply to land on the funding account");
    poll_until("genesis supply to land", 60, || async {
        Ok(account_balance(&ctx, funding_id).await? == u128::from(funding_balance))
    })
    .await?;
    info!(%funding_id, funding_balance, "Funded demo account");

    let ownership_id = new_account(&mut ctx, false, None)
        .await
        .context("Failed to create a fresh stake ownership account")?;
    tracing::info!(%ownership_id, "Fresh stake ownership account");

    let funds_id = system_accounts::stake_funds_account_id(&ownership_id);

    let config_id = system_accounts::sequencer_stake_config_account_id();
    let stake_id = programs::sequencer_stake_account_id();

    info!(
        sequencer_key = %hex::encode(demo_sequencer_key.to_bytes()),
        "Submitting Stake transaction"
    );
    SequencerStake(ctx.wallet())
        .send_stake(
            AccountIdentity::Public(ownership_id),
            AccountIdentity::Public(funding_id),
            demo_stake_key,
            u128::from(funding_balance),
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit Stake transaction: {err:?}"))?;

    info!("Waiting for the Stake transaction's block to land");
    poll_until("stake to take ownership", 60, || async {
        Ok(!get_account(&ctx, ownership_id)
            .await?
            .data
            .actor_state(stake_id)
            .is_empty())
    })
    .await?;

    let ownership_account = get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the stake ownership account")?;
    assert!(
        !ownership_account.data.actor_state(stake_id).is_empty(),
        "ownership account should now hold a sequencer_stake record"
    );
    let staked_balance = account_balance(&ctx, funds_id).await?;
    assert_eq!(
        staked_balance,
        u128::from(funding_balance),
        "the funds PDA should hold the staked balance"
    );
    let record = sequencer_stake_core::StakeRecord::from_bytes(
        ownership_account.data.actor_state(stake_id).as_ref(),
    )
    .context("ownership account data did not decode as a StakeRecord")?;
    assert_eq!(record.sequencer_key, demo_stake_key);
    info!(
        staked_balance,
        sequencer_key = %hex::encode(record.sequencer_key),
        "Ownership account confirmed"
    );

    let channel_id = bedrock_channel_id();
    let observer = spawn_channel_observer(ctx.bedrock_addr(), channel_id)?;

    // The committee-config update is a separate tx from the block's own
    // publish, so it may land a moment later — poll a few times before failing.
    let mut committee = None;
    for _ in 0..10 {
        let accredited = observer
            .ask(GetAccreditedKeys { channel_id })
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
        accredited_keys = committee.keys.len(),
        "Bedrock channel now accredits the demo sequencer key, self-join complete"
    );

    // Only now start a node behind the key, against a channel that already has a chain.
    let (joiner, _joiner_home) = SequencerSetup::new(fast_blocks(), ctx.bedrock_addr())
        .with_channel_id(channel_id)
        .with_channel_signing_key(UnsecuredEd25519Key::from_bytes(&JOINER_SIGNING_KEY))
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
    tracing::info!(joined_at, "Joining sequencer synced to block");

    // A block's fee transaction pays its producer's ownership account, and the leader holds the
    // joiner's blocks only once Bedrock carries them.
    poll_until("a block built by the joining sequencer to land", 180, {
        let leader_client = ctx.sequencer_client();
        move || async move {
            let tip = leader_client.get_last_block_id().await?;
            for id in joined_at.saturating_add(1)..=tip {
                let block = leader_client.get_block(id).await?;
                if block.as_ref().and_then(producer_account) == Some(ownership_id) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    })
    .await?;
    info!("A block built by the joining sequencer landed on the leader's chain");

    // Both nodes agree, block for block, over everything they share.
    wait_for_same_chain(ctx.sequencer_client(), &joiner_client)
        .await
        .context("Leader (A) and joining sequencer (B) disagree on the chain")?;
    info!("Leader and joining sequencer agree on their shared blocks");

    // Exit flow: full UnstakeRequest, wait for the committee removal to land on
    // Bedrock, then check the sequencer's own FinalizeUnstake releases the stake.
    //
    // Unstake recipient is freely chosen during the request.
    let destination_id = funding_id;
    let destination_balance = account_balance(&ctx, destination_id).await?;

    let submit_unstake_request = async |requested_at: u64| -> Result<HashType> {
        let unstake_request_message =
            Program::serialize_message(sequencer_stake_core::Message::UnstakeRequest {
                sequencer_key: demo_stake_key,
                amount: u128::from(funding_balance),
                destination: destination_id,
                requested_at,
            })
            .context("Failed to serialize UnstakeRequest message")?;
        let tx_hash = ctx
            .wallet()
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(ownership_id).select_program_actor_state(stake_id),
                    AccountIdentity::PublicNoSign(config_id).select_program_actor_state(stake_id),
                ],
                0,
                unstake_request_message,
            )
            .await
            .map_err(|err| {
                anyhow::anyhow!("Failed to submit UnstakeRequest transaction: {err:?}")
            })?;
        info!(
            valid_up_to_block = requested_at,
            "Submitted full UnstakeRequest for the demo sequencer key"
        );
        Ok(tx_hash)
    };

    // The request expires `UNSTAKE_REQUEST_WINDOW` blocks on, and without gossip
    // only the sequencer it was sent to includes it, so a request sent while the
    // joiner holds the turn can expire unseen: send a fresh one once it has.
    let mut request: Option<(HashType, u64)> = None;
    let mut included = false;
    let mut removed = false;
    for _ in 0..60 {
        if !included {
            let last_block_id = ctx.sequencer_client().get_last_block_id().await?;
            match request {
                Some((tx_hash, _))
                    if ctx
                        .sequencer_client()
                        .get_transaction(tx_hash)
                        .await?
                        .is_some() =>
                {
                    included = true;
                }
                Some((_, requested_at)) if last_block_id <= requested_at => {}
                _ => {
                    let requested_at =
                        last_block_id.saturating_add(sequencer_stake_core::UNSTAKE_REQUEST_WINDOW);
                    request = Some((submit_unstake_request(requested_at).await?, requested_at));
                }
            }
        }

        let accredited = observer
            .ask(GetAccreditedKeys { channel_id })
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

    // The ownership account is the demo sequencer's reward target, so it holds the producer
    // payouts of the blocks it built while in the committee.
    let ownership_before_release = account_balance(&ctx, ownership_id).await?;

    // Once removed, the sequencer injects FinalizeUnstake itself; this test
    // never submits one.
    poll_until(
        "FinalizeUnstake to drain the stake funds account",
        90,
        || async { Ok(account_balance(&ctx, funds_id).await? == 0) },
    )
    .await?;

    let drained_ownership_account = get_account(&ctx, ownership_id)
        .await
        .context("Failed to read the ownership account after the release")?;
    assert_eq!(
        drained_ownership_account.data.native_balance().unwrap(),
        ownership_before_release,
        "the ownership account never custodies the stake"
    );
    assert_eq!(
        account_balance(&ctx, destination_id).await?,
        destination_balance + u128::from(funding_balance),
        "the destination receives the released stake in FinalizeUnstake itself"
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
        funding_balance,
        %destination_id,
        "FinalizeUnstake auto-included: balance sent to and received by the destination, nothing \
         left at stake"
    );

    Ok(())
}

/// The account `block` pays its producer, read from its fee transaction, which is second to last.
fn producer_account(block: &Block) -> Option<AccountId> {
    let transactions = &block.body.transactions;
    let LeeTransaction::Public(fee_tx) = transactions.get(transactions.len().checked_sub(2)?)?
    else {
        return None;
    };
    fee_invocation_payee(fee_tx).map(FeePayee::producer)
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
            .actor_state(programs::sequencer_stake_account_id())
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
