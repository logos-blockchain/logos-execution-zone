//! A committee update that no single sequencer can authorize.
//!
//! Three sequencers are staked at genesis, so the channel is created demanding
//! two signatures for its next config. A fourth key then stakes its way in.
//! The update that accredits it can only land if a peer signed the proposer's
//! transaction and the signature came back over gossip.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use integration_tests::{account_balance, get_account, init_logger, new_account};
use lee::{AccountId, PrivateKey, PublicKey, program::Program};
use log::info;
use logos_blockchain_core::mantle::{channel::ChannelState, ops::channel::Ed25519PublicKey};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
};
use sequencer_core::config::GenesisAction;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{
        MultiNodeTestContextConfig, SequencerPartialConfig, UrlProtocol, addr_to_url,
        bedrock_channel_id,
    },
};
use tokio::test;
use wallet::AccountIdentity;

/// Comfortably above `system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE`.
const FUNDING_BALANCE: u128 = 2 * system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

/// Bedrock signing key of the sequencer that stakes its way in.
const JOINER_SIGNING_KEY: [u8; 32] = [0x42; 32];

/// The committee update is its own transaction and needs peer signatures, so
/// give it several turns rather than several blocks.
const COMMITTEE_ATTEMPTS: u32 = 40;
const COMMITTEE_POLL: Duration = Duration::from_secs(3);

fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        ..SequencerPartialConfig::default()
    }
}

async fn channel_state(ctx: &TestContext) -> Result<ChannelState> {
    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.bedrock_addr())
        .context("Failed to build the Bedrock node URL")?;
    let node = NodeHttpClient::new(CommonHttpClient::new(None), bedrock_url);

    node.channel_state(bedrock_channel_id())
        .await
        .context("Failed to read Bedrock channel state")?
        .context("Bedrock channel does not exist")
}

/// Waits for the channel to accredit `key`, which takes a config update.
async fn wait_for_accreditation(ctx: &TestContext, key: Ed25519PublicKey) -> Result<ChannelState> {
    for _ in 0..COMMITTEE_ATTEMPTS {
        let state = channel_state(ctx).await?;
        if state.accredited_keys.iter().any(|live| *live == key) {
            return Ok(state);
        }
        tokio::time::sleep(COMMITTEE_POLL).await;
    }

    anyhow::bail!("the channel never accredited the joining key")
}

#[test]
async fn a_committee_update_needs_a_peer_signature() -> Result<()> {
    init_logger();

    let joiner_key = Ed25519Key::from_bytes(&JOINER_SIGNING_KEY).public_key();
    let joiner_stake_key = sequencer_stake_core::SequencerKey::new(joiner_key.to_bytes())
        .expect("a Bedrock key is a valid Ed25519 public key");

    let funding_private_key = PrivateKey::new_os_random();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_private_key));

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 3,
                bedrock_channel: bedrock_channel_id(),
            })
            .with_sequencer_partial_config(fast_blocks())
            .with_gossip()
            .with_genesis(vec![GenesisAction::SupplyAccount {
                account_id: funding_id,
                balance: FUNDING_BALANCE,
            }]),
        )
        .build()
        .await
        .context("Failed to build the three-sequencer test context")?;

    // The premise. Three staked keys put the channel's own threshold at two, so
    // the update below cannot be authorized by whoever proposes it alone.
    let genesis_state = channel_state(&ctx).await?;
    ensure!(
        genesis_state.accredited_keys.len() == 3,
        "expected three accredited keys at genesis, got {}",
        genesis_state.accredited_keys.len()
    );
    ensure!(
        genesis_state.configuration_threshold == 2,
        "three keys should ask for two signatures, got {}",
        genesis_state.configuration_threshold
    );
    info!(
        "Channel created accrediting {} keys at a configuration threshold of {}",
        genesis_state.accredited_keys.len(),
        genesis_state.configuration_threshold
    );

    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(funding_private_key);

    integration_tests::wait_until("genesis supply to land", || async {
        Ok(account_balance(&ctx, funding_id).await? == FUNDING_BALANCE)
    })
    .await?;

    let ownership_id = new_account(&mut ctx, false, None)
        .await
        .context("Failed to create a fresh stake ownership account")?;
    let funds_id = system_accounts::stake_funds_account_id(&ownership_id);

    let mover_instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: FUNDING_BALANCE,
        })
        .context("Failed to serialize mover instruction")?;
    let stake_instruction_data =
        Program::serialize_instruction(sequencer_stake_core::Instruction::Stake {
            sequencer_key: joiner_stake_key,
            amount: FUNDING_BALANCE,
            mover_account_id: programs::authenticated_transfer().id().into(),
            mover_instruction_data,
        })
        .context("Failed to serialize Stake instruction")?;

    info!(
        "Staking sequencer key {}",
        hex::encode(joiner_key.to_bytes())
    );
    ctx.wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::Public(funding_id),
                AccountIdentity::Public(ownership_id),
                AccountIdentity::PublicNoSign(funds_id),
                AccountIdentity::PublicNoSign(
                    system_accounts::sequencer_stake_config_account_id(),
                ),
            ],
            stake_instruction_data,
            programs::sequencer_stake().id().into(),
        )
        .await
        .map_err(|err| anyhow::anyhow!("Failed to submit Stake transaction: {err:?}"))?;

    integration_tests::wait_until("stake to take ownership", || async {
        Ok(get_account(&ctx, ownership_id).await?.program_owner
            == programs::sequencer_stake().id().into())
    })
    .await?;
    ensure!(
        account_balance(&ctx, funds_id).await? == FUNDING_BALANCE,
        "the funds PDA should hold the staked balance"
    );

    // What the test is actually for. Reaching four accredited keys took a
    // config update carrying two signatures, and no sequencer holds two keys,
    // so the second one crossed the mesh.
    let updated = wait_for_accreditation(&ctx, joiner_key).await?;
    ensure!(
        updated.accredited_keys.len() == 4,
        "expected four accredited keys after the join, got {}",
        updated.accredited_keys.len()
    );
    ensure!(
        updated.config_tip_hash != genesis_state.config_tip_hash,
        "the config tip should have moved"
    );
    // Four keys ask three of the next one, so the update also rewrote the bar.
    ensure!(
        updated.configuration_threshold == 3,
        "four keys should ask for three signatures, got {}",
        updated.configuration_threshold
    );
    info!(
        "Committee update landed: {} keys at a configuration threshold of {}",
        updated.accredited_keys.len(),
        updated.configuration_threshold
    );

    Ok(())
}
