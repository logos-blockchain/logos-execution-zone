#![allow(dead_code, reason = "helper module used only by FFI test binaries")]

use std::{
    ffi::{CString, c_char},
    fs::File,
    io::Write as _,
    time::Duration,
};

use anyhow::{Context as _, Result};
use core_ffi::{
    error::FfiOperationError,
    primitives::{
        result::PointerResult,
        runtime::Runtime,
        types::{
            FfiAccountId, FfiBlockId, FfiHashType, FfiOption, FfiSelector, FfiVec,
            account::FfiAccount,
            block::{FfiBlock, FfiBlockOpt},
            event::FfiEventRecord,
            transaction::FfiTransaction,
        },
    },
    sequencer::{
        SequencerServiceFFI,
        api::{
            lifecycle::InitializedSequencerServiceFFIResult,
            query::{ExecutorStatusResult, FfiExecutorState, LastBlockIdResult},
        },
    },
};
use lee::{Account, AccountId, PrivateKey, PublicAccountEvidence, PublicKey};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, UnsecuredEd25519Key};
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
};
use sequencer_service::{DepositRecipient, GenesisAction};
use tempfile::TempDir;
use test_fixtures::{
    BlockingTestContext, MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{
        MultiNodeTestContextConfig, SequencerPartialConfig, UrlProtocol, addr_to_url,
        bedrock_channel_id,
    },
    setup::SequencerSetup,
};
use wallet::{AccountIdentity, program_facades::sequencer_stake::SequencerStake};

use crate::{
    L2_TO_L1_TIMEOUT, account_balance, ffi_helpers::primitives::primitives_ffi_free_cstring,
    get_account, new_account,
};

unsafe extern "C" {
    pub unsafe fn sequencer_ffi_query_executor_status(
        sequencer: *const SequencerServiceFFI,
    ) -> ExecutorStatusResult;

    pub unsafe fn sequencer_ffi_query_last_block(
        sequencer: *const SequencerServiceFFI,
    ) -> LastBlockIdResult;

    pub unsafe fn sequencer_ffi_query_block(
        sequencer: *const SequencerServiceFFI,
        block_id: FfiBlockId,
    ) -> PointerResult<FfiBlockOpt, FfiOperationError>;

    pub unsafe fn sequencer_ffi_start_sequencer(
        runtime: *const Runtime,
        config_path: *const c_char,
    ) -> InitializedSequencerServiceFFIResult;

    pub unsafe fn sequencer_ffi_query_account(
        sequencer: *const SequencerServiceFFI,
        account_id: FfiAccountId,
    ) -> PointerResult<FfiOption<FfiAccount>, FfiOperationError>;

    pub unsafe fn sequencer_ffi_query_block_vec(
        sequencer: *const SequencerServiceFFI,
        before: FfiOption<u64>,
        limit: u64,
    ) -> PointerResult<FfiVec<FfiBlock>, FfiOperationError>;

    pub unsafe fn sequencer_ffi_query_block_by_hash(
        sequencer: *const SequencerServiceFFI,
        hash: FfiHashType,
    ) -> PointerResult<FfiBlockOpt, FfiOperationError>;

    pub unsafe fn sequencer_ffi_query_transactions_by_account(
        sequencer: *const SequencerServiceFFI,
        account_id: FfiAccountId,
        offset: u64,
        limit: u64,
    ) -> PointerResult<FfiVec<FfiTransaction>, FfiOperationError>;

    pub unsafe fn sequencer_ffi_query_events(
        sequencer: *const SequencerServiceFFI,
        from_block: u64,
        to_block: FfiOption<u64>,
        tx_hash: *const FfiHashType,
        program_account_id: *const FfiAccountId,
        selector: *const FfiSelector,
    ) -> PointerResult<FfiVec<FfiEventRecord>, FfiOperationError>;

    pub unsafe fn sequencer_ffi_stop_sequencer(sequencer: *mut SequencerServiceFFI);
}

/// Comfortably above `system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE`.
pub const FUNDING_BALANCE: u128 = 2 * system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

/// Channel signing key of the sequencer that stakes its way in.
pub const JOINER_SIGNING_KEY: [u8; 32] = [0x42; 32];

/// A leader node with an FFI node staked into its channel.
pub struct JoiningSetup {
    pub ownership_id: Option<AccountId>,
    pub sequencer_ffi: PointerResult<SequencerServiceFFI, FfiOperationError>,
    pub node: NodeHttpClient,
    // Runtime must have stable address.
    pub ctx: Box<BlockingTestContext>,
    /// The joining node's home. Its `RocksDB` lives in here, so it has to
    /// outlive the sequencer; dropping it pulls the database out from under a
    /// node that is still running.
    pub sequencer_home: TempDir,
}

/// Short block cadence for the joining.
#[must_use]
pub fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        priority_fee_percent: 150,
        ..SequencerPartialConfig::default()
    }
}

/// Waits until `sequencer` is online, i.e. done bootstrapping from the channel.
pub fn wait_for_sequencer_ffi_online(sequencer: &SequencerServiceFFI) -> Result<()> {
    const TIMEOUT: Duration = Duration::from_secs(360);

    let start = std::time::Instant::now();
    loop {
        // SAFETY: `sequencer` is a valid reference for the duration of the call.
        let status = unsafe { sequencer_ffi_query_executor_status(std::ptr::from_ref(sequencer)) };
        if status.error.is_error() {
            anyhow::bail!("Failed to query the executor status: {:?}", status.error);
        }
        if status.state == FfiExecutorState::Online {
            return Ok(());
        }

        let replayed_height = status.has_height.then_some(status.height);
        if start.elapsed() >= TIMEOUT {
            anyhow::bail!(
                "Sequencer FFI did not come online within {TIMEOUT:?}, \
                 last seen bootstrapping at height {replayed_height:?}"
            );
        }
        log::debug!("Sequencer FFI is still bootstrapping, at height {replayed_height:?}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn wait_for_sequencer_ffi_block(
    sequencer: &SequencerServiceFFI,
    min_block_id: u64,
) -> Result<u64> {
    let start = std::time::Instant::now();
    loop {
        // SAFETY: `sequencer` is a valid reference for the duration of the call.
        let res = unsafe { sequencer_ffi_query_last_block(std::ptr::from_ref(sequencer)) };
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

#[must_use]
pub fn queried_account(sequencer: &SequencerServiceFFI, account_id: AccountId) -> Option<Account> {
    // SAFETY: `sequencer` is a valid reference for the duration of the call.
    let res =
        unsafe { sequencer_ffi_query_account(std::ptr::from_ref(sequencer), account_id.into()) };
    assert!(res.error.is_ok(), "Failed to fetch account {account_id}");
    // SAFETY: the query returned a valid option, read and converted exactly once.
    let account: Option<FfiAccount> = unsafe { res.value.read() }.into();
    account.map(|account| (&account).try_into().expect("Data must fit"))
}

/// Sets up blocking context with one leader node
/// and joins FFI node through staking flow.
pub fn joining_setup_with_stake() -> Result<JoiningSetup> {
    let joining_sequencer_key = Ed25519Key::from_bytes(&JOINER_SIGNING_KEY).public_key();
    let joining_stake_key =
        sequencer_stake_core::SequencerKey::new(joining_sequencer_key.to_bytes())
            .expect("a channel signing public key is a valid Ed25519 public key");

    let funding_private_key = PrivateKey::new_os_random();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_private_key));

    // Boxing to make pointers non-movable.
    let mut ctx = Box::new(
        MultiZoneTestContextBuilder::default()
            .with_zone(
                ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                    .with_sequencer_partial_config(fast_blocks())
                    .with_genesis(vec![GenesisAction::SupplyAccount {
                        recipient: DepositRecipient::Identified(PublicAccountEvidence::Key(
                            PublicKey::new_from_private_key(&funding_private_key),
                        )),
                        balance: FUNDING_BALANCE.try_into().expect("Must fit"),
                    }]),
            )
            .build_blocking()
            .context("Failed to build test context")?,
    );

    // Import the funding key directly; it's not one of the wallet's default accounts.
    ctx.ctx_mut()
        .wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(funding_private_key);

    log::info!("Waiting for the genesis supply to land on the funding account");
    ctx.block_on(|ctx| {
        poll_until("genesis supply to land", 60, || async {
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

    log::info!(
        "Submitting Stake transaction for sequencer key {}",
        hex::encode(joining_sequencer_key.to_bytes())
    );
    let stake_id = programs::sequencer_stake_account_id();
    ctx.block_on(|ctx| async {
        SequencerStake(ctx.wallet())
            .send_stake(
                AccountIdentity::Public(ownership_id),
                AccountIdentity::Public(funding_id),
                joining_stake_key,
                FUNDING_BALANCE,
            )
            .await
            .map_err(|err| anyhow::anyhow!("Failed to submit Stake transaction: {err:?}"))
    })?;

    log::info!("Waiting for the Stake transaction's block to land");

    ctx.block_on(|ctx| {
        poll_until("stake to take ownership", 60, || async {
            Ok(!get_account(ctx, ownership_id)
                .await?
                .data
                .actor_state(stake_id)
                .is_empty())
        })
    })?;

    // The fixture orders its initial accounts by id so `existing_public_accounts()` is stable.
    // The funding key is only needed to sign the stake, so drop it rather than leave a randomly
    // keyed, now empty account in that list.
    ctx.ctx_mut()
        .wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .remove_imported_public_account(&funding_id);

    let ownership_account = ctx.block_on(|ctx| async {
        get_account(ctx, ownership_id)
            .await
            .context("Failed to read the stake ownership account")
    })?;
    assert!(
        !ownership_account.data.actor_state(stake_id).is_empty(),
        "ownership account should now hold a sequencer_stake record"
    );
    let staked_balance = ctx.block_on(|ctx| account_balance(ctx, funds_id))?;
    assert_eq!(
        staked_balance, FUNDING_BALANCE,
        "the funds PDA should hold the staked balance"
    );
    let record = sequencer_stake_core::StakeRecord::from_bytes(
        ownership_account.data.actor_state(stake_id).as_ref(),
    )
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
            .any(|key| *key == joining_sequencer_key.into_unverified())
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
        .with_channel_signing_key(UnsecuredEd25519Key::from_bytes(&JOINER_SIGNING_KEY))
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

    let sequencer_ffi_res =
    // SAFETY: null runtime → the FFI creates and owns its own tokio runtime,
    // so there is no external runtime whose address we must keep stable.
    unsafe { sequencer_ffi_start_sequencer(std::ptr::null(), raw_config_path) };

    // SAFETY: cstring was constructed from valid string.
    unsafe {
        primitives_ffi_free_cstring(raw_config_path);
    }

    if sequencer_ffi_res.error.is_error() {
        anyhow::bail!("Sequencer FFI error {:?}", sequencer_ffi_res.error);
    }

    // SAFETY: the start succeeded, so the pointer is valid.
    if let Err(err) = wait_for_sequencer_ffi_online(unsafe { &*sequencer_ffi_res.value }) {
        // SAFETY: the pointer is valid and not used after this.
        unsafe {
            sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
        }
        return Err(err);
    }
    log::info!("Joining sequencer is online");

    Ok(JoiningSetup {
        node,
        ownership_id: Some(ownership_id),
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home: temp_sequencer_dir,
        ctx,
    })
}

/// Sets up blocking context with one leader node
/// and joins FFI node without staking flow.
pub fn joining_setup_no_stake() -> Result<JoiningSetup> {
    let ctx = Box::new(
        MultiZoneTestContextBuilder::default()
            .with_zone(
                ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                    .with_sequencer_partial_config(fast_blocks())
                    .with_genesis(vec![]),
            )
            .build_blocking()
            .context("Failed to build test context")?,
    );

    let bedrock_url = addr_to_url(UrlProtocol::Http, ctx.ctx().bedrock_addr())
        .context("Failed to build the Bedrock node URL")?;
    let node = NodeHttpClient::new(CommonHttpClient::new(None), bedrock_url);

    // Only now start a node behind the key, against a channel that already has a chain.
    let setup = SequencerSetup::new(fast_blocks(), ctx.ctx().bedrock_addr())
        .with_channel_id(bedrock_channel_id())
        .with_channel_signing_key(UnsecuredEd25519Key::from_bytes(&JOINER_SIGNING_KEY))
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

    let borrowed_runtime =
        // SAFETY: Runtime from context is valid.
        unsafe { core_ffi::primitives::runtime::Runtime::from_borrowed(ctx.runtime()) };

    let sequencer_ffi_res =
        // SAFETY: Runtime borrowed from context is valid.
        unsafe { sequencer_ffi_start_sequencer(&raw const borrowed_runtime, raw_config_path) };

    // SAFETY: cstring was constructed from valid string.
    unsafe {
        primitives_ffi_free_cstring(raw_config_path);
    }

    if sequencer_ffi_res.error.is_error() {
        anyhow::bail!("Sequencer FFI error {:?}", sequencer_ffi_res.error);
    }

    // SAFETY: the start succeeded, so the pointer is valid.
    if let Err(err) = wait_for_sequencer_ffi_online(unsafe { &*sequencer_ffi_res.value }) {
        // SAFETY: the pointer is valid and not used after this.
        unsafe {
            sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
        }
        return Err(err);
    }
    log::info!("Joining sequencer is online");

    Ok(JoiningSetup {
        node,
        ownership_id: None,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home: temp_sequencer_dir,
        ctx,
    })
}

pub fn joining_setup(stake: bool) -> Result<JoiningSetup> {
    if stake {
        joining_setup_with_stake()
    } else {
        joining_setup_no_stake()
    }
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
