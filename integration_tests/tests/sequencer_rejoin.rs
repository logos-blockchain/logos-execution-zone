#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! B unstakes in full, leaves the committee, gets its stake back, then rejoins.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use integration_tests::{
    account_balance, assert_same_chain, committee, get_account, init_logger, wait_until,
};
use lee::{AccountId, PublicKey, program::Program};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{self, MultiNodeTestContextConfig, SequencerPartialConfig},
    spawn_channel_observer,
};
use tokio::test;
use wallet::{AccountIdentity, AccountMention};

/// What genesis stakes each founding sequencer.
const STAKE: u128 = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

#[test]
async fn a_sequencer_leaves_the_committee_and_rejoins() -> Result<()> {
    init_logger();

    let channel = config::bedrock_channel_id();
    let partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        // Covers the storage price doubling at the devnet's first epoch rotations.
        priority_fee_percent: 150,
        ..SequencerPartialConfig::default()
    };

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                bedrock_channel: channel,
            })
            .with_sequencer_partial_config(partial)
            .with_gossip(),
        )
        .build()
        .await
        .context("Failed to build the two-sequencer test context")?;

    let key_b = config::sequencer_signing_key_from_seed(1).public_key();
    let stake_key_b = sequencer_stake_core::SequencerKey::new(key_b.to_bytes())
        .context("Sequencer B's Bedrock key is not a valid Ed25519 point")?;

    let observer = spawn_channel_observer(ctx.bedrock_addr(), channel).await?;

    // B's genesis stake sits on an account only this key can sign for.
    let owner_b = config::founding_stake_owner_key(1)?;
    let ownership_b = AccountId::from(&PublicKey::new_from_private_key(&owner_b));
    let funds_b = system_accounts::stake_funds_account_id(&ownership_b);
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(owner_b);

    let config_id = system_accounts::sequencer_stake_config_account_id();
    let stake_id = AccountId::from_builtin_program(programs::sequencer_stake().id());

    let settlement = AccountId::from(&PublicKey::new_from_private_key(
        &config::default_public_accounts_for_wallet()[0].0,
    ));

    wait_until("both staked keys to be accredited", || async {
        Ok(committee(&observer).await?.0.contains(&key_b.to_bytes()))
    })
    .await?;
    info!("Both sequencers accredited from channel creation");

    // B leaves.
    let settlement_before = account_balance(&ctx, settlement).await?;
    send_stake_tx(
        &ctx,
        vec![
            AccountIdentity::Public(ownership_b).select_program_shard(stake_id),
            AccountIdentity::PublicNoSign(config_id).select_program_shard(stake_id),
        ],
        &sequencer_stake_core::Instruction::UnstakeRequest {
            amount: STAKE,
            destination: settlement,
        },
    )
    .await
    .context("Failed to submit B's UnstakeRequest")?;
    info!("B requested a full unstake");

    wait_until("B to leave the committee", || async {
        Ok(!committee(&observer).await?.0.contains(&key_b.to_bytes()))
    })
    .await?;
    info!("B removed from the Bedrock committee");

    wait_until("B's stake to be released", || async {
        Ok(get_account(&ctx, funds_b).await?.data.balance().unwrap() == 0)
    })
    .await?;
    ensure!(
        account_balance(&ctx, settlement).await? == settlement_before + STAKE,
        "the released stake should have reached the settlement account"
    );
    ensure!(
        stake_entry(&ctx, stake_key_b).await?.is_none(),
        "a fully released key should have no config entry left"
    );
    info!("B's stake released in full");

    // B rejoins on the same ownership account, which stays claimed after an exit.
    let mover_instruction_data =
        Program::serialize_instruction(lee_core::native_token::Instruction::Transfer {
            amount: STAKE,
        })
        .context("Failed to serialize the mover instruction")?;
    send_stake_tx(
        &ctx,
        vec![
            AccountIdentity::Public(settlement).balance(),
            AccountIdentity::Public(ownership_b).select_program_shard(stake_id),
            AccountIdentity::PublicNoSign(funds_b).balance(),
            AccountIdentity::PublicNoSign(config_id).select_program_shard(stake_id),
        ],
        &sequencer_stake_core::Instruction::Stake {
            sequencer_key: stake_key_b,
            amount: STAKE,
            mover_account_id: lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID,
            mover_instruction_data,
        },
    )
    .await
    .context("Failed to submit B's re-stake")?;

    wait_until("B's re-stake to land", || async {
        Ok(get_account(&ctx, funds_b).await?.data.balance().unwrap() == STAKE)
    })
    .await?;
    info!("B staked again");

    wait_until("B to be accredited again", || async {
        Ok(committee(&observer).await?.0.contains(&key_b.to_bytes()))
    })
    .await?;
    info!("B back in the Bedrock committee");

    // Rejoining is only real if B writes to the channel again.
    wait_until("the round-robin turn to reach B again", || async {
        Ok(committee(&observer).await?.1 == Some(key_b))
    })
    .await?;

    let a = ctx
        .sequencer_client_by_node_ids(channel, 0)
        .context("Missing sequencer A")?;
    let b = ctx
        .sequencer_client_by_node_ids(channel, 1)
        .context("Missing sequencer B")?;
    let resumed_at = a.get_last_block_id().await?;
    wait_until("the chain to advance past B's rejoin", || async {
        Ok(a.get_last_block_id().await? > resumed_at)
    })
    .await?;
    assert_same_chain(a, b).await?;
    info!("B produces again and both sequencers agree on the chain");

    Ok(())
}

/// Sends `instruction` to `sequencer_stake` over `accounts`.
async fn send_stake_tx(
    ctx: &TestContext,
    accounts: Vec<AccountMention>,
    instruction: &sequencer_stake_core::Instruction,
) -> Result<()> {
    let data = Program::serialize_instruction(instruction.clone())
        .context("Failed to serialize the sequencer_stake instruction")?;
    ctx.wallet()
        .send_pub_tx(
            accounts,
            data,
            AccountId::from_builtin_program(programs::sequencer_stake().id()),
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit sequencer_stake transaction: {err:?}"))?;
    Ok(())
}

/// The `sequencer_stake` config entry for `sequencer_key`, if any.
async fn stake_entry(
    ctx: &TestContext,
    sequencer_key: sequencer_stake_core::SequencerKey,
) -> Result<Option<sequencer_stake_core::SequencerEntry>> {
    let account = get_account(ctx, system_accounts::sequencer_stake_config_account_id())
        .await
        .context("Failed to read the sequencer_stake config account")?;
    let config = sequencer_stake_core::SequencerStakeConfig::from_bytes(
        account
            .data
            .shard(AccountId::from_builtin_program(
                programs::sequencer_stake().id(),
            ))
            .as_ref(),
    )
    .context("config account data did not decode as a SequencerStakeConfig")?;
    Ok(config.entries.get(&sequencer_key).copied())
}
