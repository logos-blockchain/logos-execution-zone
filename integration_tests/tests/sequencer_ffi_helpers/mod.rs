#![allow(dead_code, reason = "helper module used only by FFI test binaries")]

use std::{
    ffi::{CString, c_char},
    fs::File,
    io::Write as _,
    time::Duration,
};

use anyhow::{Context as _, Result};
use integration_tests::{L2_TO_L1_TIMEOUT, account_balance, get_account, new_account};
use lee::{AccountId, PrivateKey, PublicKey, program::Program};
use logos_blockchain_key_management_system_service::keys::Ed25519PublicKey;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
};
use sequencer_core::block_publisher::Ed25519Key;
use sequencer_ffi::{
    OperationStatus, Runtime, SequencerServiceFFI,
    api::{
        PointerResult,
        lifecycle::InitializedSequencerServiceFFIResult,
        query::LastBlockIdResult,
        types::{
            FfiAccountId, FfiBlockId,
            account::FfiAccount,
            block::{FfiBlock, FfiBlockOpt},
        },
    },
};
use sequencer_service::GenesisAction;
use test_fixtures::{
    BlockingTestContext, MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{
        MultiNodeTestContextConfig, SequencerPartialConfig, UrlProtocol, addr_to_url,
        bedrock_channel_id,
    },
    setup::SequencerSetup,
};
use wallet::AccountIdentity;

unsafe extern "C" {
    pub unsafe fn query_last_block(sequencer: *const SequencerServiceFFI) -> LastBlockIdResult;

    pub unsafe fn query_block(
        sequencer: *const SequencerServiceFFI,
        block_id: FfiBlockId,
    ) -> PointerResult<FfiBlockOpt, OperationStatus>;

    pub unsafe fn start_sequencer(
        runtime: *const Runtime,
        config_path: *const c_char,
    ) -> InitializedSequencerServiceFFIResult;

    pub unsafe fn query_account(
        sequencer: *const SequencerServiceFFI,
        account_id: FfiAccountId,
    ) -> PointerResult<FfiAccount, OperationStatus>;

    pub unsafe fn free_ffi_block(val: FfiBlock);
}

/// Comfortably above `system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE`.
pub const FUNDING_BALANCE: u128 = 2 * system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

/// Bedrock signing key of the sequencer that stakes its way in.
pub const JOINER_SIGNING_KEY: [u8; 32] = [0x42; 32];

/// Short block cadence for the joining.
pub fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        priority_fee_percent: 150,
        ..SequencerPartialConfig::default()
    }
}

pub fn wait_for_sequencer_ffi_block(
    sequencer: &SequencerServiceFFI,
    min_block_id: u64,
) -> Result<u64> {
    let start = std::time::Instant::now();
    loop {
        // SAFETY: `sequencer` is a valid reference for the duration of the call.
        let res = unsafe { query_last_block(std::ptr::from_ref(sequencer)) };
        if res.error.is_ok() && res.is_some && res.block_id >= min_block_id {
            return Ok(res.block_id);
        }

        if start.elapsed() >= L2_TO_L1_TIMEOUT {
            anyhow::bail!(
                "Sequencer FFI did not reach block {min_block_id} within {:?}. Last observed block id: {}",
                L2_TO_L1_TIMEOUT,
                res.block_id
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// Sets up blocking context with one leader node
/// and joins FFI node through staking flow.
pub fn joining_setup() -> Result<(
    BlockingTestContext,
    NodeHttpClient,
    AccountId,
    SequencerServiceFFI,
)> {
    let joining_sequencer_key = Ed25519Key::from_bytes(&JOINER_SIGNING_KEY).public_key();
    let joining_stake_key =
        sequencer_stake_core::SequencerKey::new(joining_sequencer_key.to_bytes())
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
        .build_blocking()
        .context("Failed to build test context")?;

    // Import the funding key directly; it's not one of the wallet's default accounts.
    ctx.ctx_mut()
        .wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(funding_private_key);

    log::info!("Waiting for the genesis supply to land on the funding account");
    ctx.block_on(|ctx| {
        poll_until("genesis supply to land", 30, || async {
            Ok(account_balance(ctx, funding_id).await? == FUNDING_BALANCE)
        })
    })?;
    log::info!("Funded joining account {funding_id} with {FUNDING_BALANCE} native balance");

    let ownership_id = ctx.block_on_mut(|ctx| async {
        new_account(ctx, false, None)
            .await
            .context("Failed to create a fresh stake ownership account")
    })?;
    log::info!("Fresh stake ownership account: {ownership_id}");

    let funds_id = system_accounts::stake_funds_account_id(&ownership_id);

    let mover_instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: FUNDING_BALANCE,
        })
        .context("Failed to serialize mover instruction")?;
    let stake_instruction_data =
        Program::serialize_instruction(sequencer_stake_core::Instruction::Stake {
            sequencer_key: joining_stake_key,
            amount: FUNDING_BALANCE,
            mover_account_id: programs::authenticated_transfer().id().into(),
            mover_instruction_data,
        })
        .context("Failed to serialize Stake instruction")?;

    log::info!(
        "Submitting Stake transaction for sequencer key {}",
        hex::encode(joining_sequencer_key.to_bytes())
    );
    let config_id = system_accounts::sequencer_stake_config_account_id();
    ctx.block_on(|ctx| async {
        ctx.wallet()
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(funding_id),
                    AccountIdentity::Public(ownership_id),
                    AccountIdentity::PublicNoSign(funds_id),
                    AccountIdentity::PublicNoSign(config_id),
                ],
                stake_instruction_data,
                programs::sequencer_stake().id().into(),
            )
            .await
            .map_err(|err| anyhow::anyhow!("Failed to submit Stake transaction: {err:?}"))
    })?;

    log::info!("Waiting for the Stake transaction's block to land");

    ctx.block_on(|ctx| {
        poll_until("stake to take ownership", 30, || async {
            Ok(get_account(ctx, ownership_id).await?.program_owner
                == programs::sequencer_stake().id().into())
        })
    })?;

    let ownership_account = ctx.block_on(|ctx| async {
        get_account(ctx, ownership_id)
            .await
            .context("Failed to read the stake ownership account")
    })?;
    assert_eq!(
        ownership_account.program_owner,
        programs::sequencer_stake().id().into(),
        "ownership account should now be owned by sequencer_stake"
    );
    let staked_balance = ctx.block_on(|ctx| account_balance(ctx, funds_id))?;
    assert_eq!(
        staked_balance, FUNDING_BALANCE,
        "the funds PDA should hold the staked balance"
    );
    let record = sequencer_stake_core::StakeRecord::from_bytes(ownership_account.data.as_ref())
        .context("ownership account data did not decode as a StakeRecord")?;
    assert_eq!(record.sequencer_key, joining_stake_key);
    log::info!(
        "Ownership account confirmed: {staked_balance} staked for sequencer key {}",
        hex::encode(record.sequencer_key)
    );

    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.ctx().bedrock_addr())
        .context("Failed to build the Bedrock node URL")?;
    let node = NodeHttpClient::new(CommonHttpClient::new(None), bedrock_url);

    // The committee-config update is a separate tx from the block's own
    // publish, so it may land a moment later — poll a few times before failing.
    let mut channel_state = None;
    for _ in 0..10 {
        let state = ctx
            .runtime()
            .block_on(node.channel_state(bedrock_channel_id()))
            .context("Failed to read Bedrock channel state")?
            .context("Bedrock channel does not exist")?;

        if state
            .accredited_keys
            .iter()
            .any(|key: &Ed25519PublicKey| *key == joining_sequencer_key)
        {
            channel_state = Some(state);
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    let channel_state = channel_state.context(
        "joining sequencer key should have been discovered and accredited after the Stake
    transaction",
    )?;
    log::info!(
        "Bedrock channel now accredits {} key(s), including the joining sequencer key — self-join
    complete",
        channel_state.accredited_keys.len()
    );

    // Only now start a node behind the key, against a channel that already has a chain.
    let setup = SequencerSetup::new(fast_blocks(), ctx.ctx().bedrock_addr())
        .with_channel_id(bedrock_channel_id())
        .with_bedrock_signing_key(JOINER_SIGNING_KEY)
        .joining_existing_channel();

    let temp_sequencer_dir =
        tempfile::tempdir().context("Failed to create temp dir for sequencer home")?;

    let config = setup.prepare_sequencers_config(temp_sequencer_dir.path().to_owned())?;

    // Put sequecner config at temp sequencer dir
    let config_json = serde_json::to_vec(&config)?;
    let config_path = temp_sequencer_dir.path().join("config.json");
    let mut file = File::create(config_path.as_path())?;
    file.write_all(&config_json)?;
    file.flush()?;

    let config_c_string = CString::new(config_path.to_str().unwrap())?;

    let raw_config_path = config_c_string.into_raw();

    let res =
    // SAFETY: null runtime → the FFI creates and owns its own tokio runtime,
    // so there is no external runtime whose address we must keep stable.
    unsafe { start_sequencer(std::ptr::null(), raw_config_path) };

    if res.error.is_error() {
        anyhow::bail!("Sequencer FFI error {:?}", res.error);
    }

    let sequencer_ffi =
    // SAFETY: FFI ensures validity of value.
    unsafe { std::ptr::read(res.value) };

    Ok((ctx, node, ownership_id, sequencer_ffi))
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
