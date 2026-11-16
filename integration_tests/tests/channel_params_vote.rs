//! Channel params change once two thirds of the accredited keys vote for them.
//!
//! Three sequencers are staked at genesis, so one vote changes nothing, and
//! withdrawing it leaves no vote. Two votes then replace the params: the
//! sequencer admits transactions against the new `max_block_size`, and the
//! Bedrock channel takes the new posting params through a config update that
//! needs a peer's signature.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::{collections::BTreeMap, fmt::Debug, time::Duration};

use anyhow::{Context as _, Result, ensure};
use common::transaction::LeeTransaction;
use integration_tests::{get_account, init_logger, wait_for_inclusion, wait_until};
use lee::{AccountId, Actor, PrivateKey, PublicKey};
use lee_core::account::Nonce;
use logos_blockchain_core::mantle::channel::ChannelState;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
};
use sequencer_service_rpc::RpcClient as _;
use sequencer_stake_core::{ChannelParams, SequencerStakeConfig};
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{
        self, MultiNodeTestContextConfig, SequencerPartialConfig, UrlProtocol, addr_to_url,
        bedrock_channel_id,
    },
};
use tokio::test;
use wallet::program_facades::sequencer_stake::SequencerStake;

async fn channel_state(ctx: &TestContext) -> Result<ChannelState> {
    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.bedrock_addr())
        .context("Failed to build the Bedrock node URL")?;
    let node = NodeHttpClient::new(CommonHttpClient::new(None), bedrock_url);

    node.channel_state(bedrock_channel_id())
        .await
        .context("Failed to read Bedrock channel state")?
        .context("Bedrock channel does not exist")
}

async fn stake_config(ctx: &TestContext) -> Result<SequencerStakeConfig> {
    let account = get_account(ctx, system_accounts::sequencer_stake_config_account_id())
        .await
        .context("Failed to read the sequencer_stake config account")?;
    SequencerStakeConfig::from_bytes(
        account
            .data
            .actor_state(programs::sequencer_stake_account_id())
            .as_ref(),
    )
    .context("config account data did not decode as a SequencerStakeConfig")
}

/// Imports founding sequencer `index`'s ownership key into the wallet, and returns that account
/// with a funded wallet account to pay its fees.
///
/// A founding ownership account holds only what its sequencer has earned producing blocks.
fn founding_owner(ctx: &mut TestContext, index: usize) -> Result<(AccountId, AccountId)> {
    let owner = config::founding_stake_owner_key(index)?;
    let ownership = AccountId::from(&PublicKey::new_from_private_key(&owner));
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(owner);
    let payer = AccountId::from(&PublicKey::new_from_private_key(
        &config::default_public_accounts_for_wallet()[0].0,
    ));
    Ok((ownership, payer))
}

/// Sends founding sequencer `index`'s vote for `params` and waits for its block.
async fn vote(ctx: &mut TestContext, index: usize, params: ChannelParams) -> Result<()> {
    let (ownership, payer) = founding_owner(ctx, index)?;
    let tx_hash = SequencerStake(ctx.wallet())
        .send_params_vote(ownership, params, Some(payer))
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit sequencer {index}'s vote: {err:?}"))?;
    wait_for_inclusion(ctx, tx_hash).await
}

/// Withdraws founding sequencer `index`'s vote and waits for its block.
async fn withdraw_vote(ctx: &mut TestContext, index: usize) -> Result<()> {
    let (ownership, payer) = founding_owner(ctx, index)?;
    let tx_hash = SequencerStake(ctx.wallet())
        .send_params_vote_withdrawal(ownership, Some(payer))
        .await
        .map_err(|err| {
            anyhow::anyhow!("Failed to submit sequencer {index}'s withdrawal: {err:?}")
        })?;
    wait_for_inclusion(ctx, tx_hash).await
}

/// A signed but unfunded `WriteSegment` carrying `bytecode_len` bytes, which admission
/// size-checks before the fee screen refuses it.
fn unfunded_segment_write(bytecode_len: usize) -> Result<LeeTransaction> {
    let segment_key = PrivateKey::try_new([220; 32])?;
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(&segment_key));
    let segment = Actor::new(segment_id, lee_core::program::PROGRAM_LOADER_ACCOUNT_ID);
    let message = lee::public_transaction::Message::try_new(
        segment,
        vec![segment],
        BTreeMap::from([(segment_id, Nonce(0))]),
        program_loader_core::Message::WriteSegment {
            bytecode: vec![0_u8; bytecode_len],
            next_segment: None,
        },
    )?;
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&segment_key]);
    Ok(LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        witness_set,
    )))
}

/// Whether the sequencer refused a submission for its size.
fn refused_as_too_large<T, E: Debug>(result: &Result<T, E>) -> bool {
    result
        .as_ref()
        .is_err_and(|err| format!("{err:?}").contains("Transaction too large"))
}

#[test]
async fn channel_params_change_once_two_thirds_of_the_committee_vote() -> Result<()> {
    init_logger();

    let partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        // Covers the storage price doubling at the devnet's first epoch rotations.
        priority_fee_percent: 150,
        ..SequencerPartialConfig::default()
    };
    let genesis_params = partial.channel_params;
    let new_params = ChannelParams {
        posting_timeframe: genesis_params.posting_timeframe.saturating_add(10),
        posting_timeout: genesis_params.posting_timeout.saturating_add(5),
        max_block_size: 512 * 1024,
        ..genesis_params
    };

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 3,
                bedrock_channel: bedrock_channel_id(),
            })
            .with_sequencer_partial_config(partial)
            .with_gossip(),
        )
        .build()
        .await
        .context("Failed to build the three-sequencer test context")?;

    let genesis_state = channel_state(&ctx).await?;
    ensure!(
        genesis_state.accredited_keys.len() == 3,
        "expected three accredited keys at genesis, got {}",
        genesis_state.accredited_keys.len()
    );

    // Its bytecode alone fills the voted limit, so only the voted params refuse it on size.
    let segment_write = unfunded_segment_write(usize::try_from(new_params.max_block_size)?)?;
    let before_vote = ctx
        .sequencer_client()
        .send_transaction(segment_write.clone())
        .await;
    ensure!(
        !refused_as_too_large(&before_vote),
        "the genesis max_block_size already refuses the test transaction on size"
    );

    vote(&mut ctx, 0, new_params).await?;
    let after_one = stake_config(&ctx).await?;
    ensure!(
        after_one.channel_params == Some(genesis_params),
        "one vote of three must not change the params"
    );
    ensure!(
        after_one.params_votes.len() == 1,
        "the first vote should be on record, got {} votes",
        after_one.params_votes.len()
    );
    tracing::info!("One vote recorded; the params are unchanged");

    withdraw_vote(&mut ctx, 0).await?;
    ensure!(
        stake_config(&ctx).await?.params_votes.is_empty(),
        "the withdrawn vote should be gone"
    );
    tracing::info!("The withdrawn vote is gone");

    vote(&mut ctx, 0, new_params).await?;
    vote(&mut ctx, 1, new_params).await?;
    let after_two = stake_config(&ctx).await?;
    ensure!(
        after_two.channel_params == Some(new_params),
        "two votes of three should replace the params, got {:?}",
        after_two.channel_params
    );
    ensure!(
        after_two.params_votes.is_empty(),
        "applying the params should clear every vote"
    );
    tracing::info!("Two votes of three replaced the params");

    wait_until(
        "the sequencer to refuse a transaction over the voted max_block_size",
        || async {
            let result = ctx
                .sequencer_client()
                .send_transaction(segment_write.clone())
                .await;
            Ok(refused_as_too_large(&result))
        },
    )
    .await?;
    tracing::info!("The sequencer admits transactions against the voted max_block_size");

    wait_until(
        "the Bedrock channel to take the new posting params",
        || async {
            let state = channel_state(&ctx).await?;
            Ok(
                u32::from(state.posting_timeframe) == new_params.posting_timeframe
                    && u32::from(state.posting_timeout) == new_params.posting_timeout,
            )
        },
    )
    .await?;
    tracing::info!("The Bedrock channel follows the voted posting params");

    Ok(())
}
