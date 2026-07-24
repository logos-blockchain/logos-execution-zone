use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use indexer_service::{ChannelId, IndexerHandle};
use lee::{AccountId, PrivateKey, PublicKey};
use log::{debug, warn};
use sequencer_core::block_store::{DbDump, SequencerStore};
use sequencer_service::{GenesisAction, SequencerHandle};
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{
    WalletCore,
    cli::{Command, SubcommandReturnValue, programs::vault::VaultSubcommand},
    config::WalletConfigOverrides,
};

use crate::{
    BEDROCK_SERVICE_PORT, BEDROCK_SERVICE_WITH_OPEN_PORT,
    config::{self, InitialPrivateAccountForWallet},
    private_mention, public_mention,
};

/// How to initialize the sequencer's database.
pub enum SequencerInit<'dump> {
    /// Apply these genesis actions from scratch.
    Genesis(Vec<GenesisAction>),
    /// Restore an existing chain from a prebuilt dump (genesis actions are then irrelevant).
    Prebuilt(&'dump DbDump),
}

/// Committed single-file dump of the prebuilt sequencer database (`just regenerate-test-fixture`).
#[must_use]
pub fn prebuilt_sequencer_db_dump_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/prebuilt_sequencer_db.dump")
}

/// Load and deserialize the committed prebuilt-database dump.
fn load_prebuilt_dump() -> Result<DbDump> {
    let path = prebuilt_sequencer_db_dump_path();
    let bytes = std::fs::read(&path)
        .with_context(|| format!("Failed to read prebuilt db dump at {}", path.display()))?;
    DbDump::from_bytes(&bytes).context("Failed to deserialize prebuilt db dump")
}

pub async fn setup_bedrock_node() -> Result<(DockerCompose, SocketAddr)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bedrock_compose_path = PathBuf::from(manifest_dir).join("../bedrock/docker-compose.yml");

    let mut compose = DockerCompose::with_auto_client(&[bedrock_compose_path])
            .await
            .context("Failed to setup docker compose for Bedrock")?
            // Setting port to 0 to avoid conflicts between parallel tests, actual port will be retrieved after container is up
            .with_env("PORT", "0");

    #[expect(
        clippy::items_after_statements,
        reason = "This is more readable is this function used just after its definition"
    )]
    async fn up_and_retrieve_port(compose: &mut DockerCompose) -> Result<u16> {
        compose
            .up()
            .await
            .context("Failed to bring up Bedrock services")?;
        let container = compose
            .service(BEDROCK_SERVICE_WITH_OPEN_PORT)
            .with_context(|| {
                format!(
                    "Failed to get Bedrock service container `{BEDROCK_SERVICE_WITH_OPEN_PORT}`"
                )
            })?;

        let ports = container.ports().await.with_context(|| {
            format!(
                "Failed to get ports for Bedrock service container `{}`",
                container.id()
            )
        })?;
        ports
            .map_to_host_port_ipv4(BEDROCK_SERVICE_PORT)
            .with_context(|| {
                format!(
                    "Failed to retrieve host port of {BEDROCK_SERVICE_PORT} container \
                        port for container `{}`, existing ports: {ports:?}",
                    container.id()
                )
            })
    }

    let mut port = None;
    let mut attempt = 0_u32;
    let max_attempts = 5_u32;
    while port.is_none() && attempt < max_attempts {
        attempt = attempt
            .checked_add(1)
            .expect("We check that attempt < max_attempts, so this won't overflow");
        match up_and_retrieve_port(&mut compose).await {
            Ok(p) => {
                port = Some(p);
            }
            Err(err) => {
                warn!(
                    "Failed to bring up Bedrock services: {err:?}, attempt {attempt}/{max_attempts}"
                );
            }
        }
    }
    let Some(port) = port else {
        bail!("Failed to bring up Bedrock services after {max_attempts} attempts");
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    Ok((compose, addr))
}

pub async fn setup_indexer(
    bedrock_addr: SocketAddr,
    channel_id: ChannelId,
    cross_zone: Option<sequencer_core::config::CrossZoneConfig>,
) -> Result<(IndexerHandle, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    debug!(
        "Using temp indexer home at {}",
        temp_indexer_dir.path().display()
    );

    let indexer_config = config::indexer_config(bedrock_addr, channel_id, cross_zone)
        .context("Failed to create Indexer config")?;

    indexer_service::run_server(
        indexer_config,
        temp_indexer_dir.path(),
        0,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .context("Failed to run Indexer Service")
    .map(|handle| (handle, temp_indexer_dir))
}

pub async fn setup_sequencer(
    partial: config::SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    genesis_transactions: Vec<GenesisAction>,
    channel_id: ChannelId,
    cross_zone: Option<sequencer_core::config::CrossZoneConfig>,
) -> Result<(SequencerHandle, TempDir)> {
    setup_sequencer_inner(
        partial,
        bedrock_addr,
        SequencerInit::Genesis(genesis_transactions),
        channel_id,
        cross_zone,
    )
    .await
}

/// Like [`setup_sequencer`], but rebuilds the sequencer database from the committed prebuilt dump
/// so it starts from an existing chain instead of applying genesis from scratch.
pub async fn setup_sequencer_from_prebuilt(
    partial: config::SequencerPartialConfig,
    bedrock_addr: SocketAddr,
) -> Result<(SequencerHandle, TempDir)> {
    let dump = load_prebuilt_dump()?;
    setup_sequencer_inner(
        partial,
        bedrock_addr,
        SequencerInit::Prebuilt(&dump),
        config::bedrock_channel_id(),
        None,
    )
    .await
}

async fn setup_sequencer_inner(
    partial: config::SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    init: SequencerInit<'_>,
    channel_id: ChannelId,
    cross_zone: Option<sequencer_core::config::CrossZoneConfig>,
) -> Result<(SequencerHandle, TempDir)> {
    let temp_sequencer_dir =
        tempfile::tempdir().context("Failed to create temp dir for sequencer home")?;

    debug!(
        "Using temp sequencer home at {}",
        temp_sequencer_dir.path().display()
    );

    let genesis_transactions = match init {
        SequencerInit::Genesis(genesis) => genesis,
        SequencerInit::Prebuilt(dump) => {
            // `SequencerCore::open_or_create_store` looks for `<home>/rocksdb`.
            let dst = temp_sequencer_dir.path().join("rocksdb");
            SequencerStore::restore_db_from_dump(&dst, dump)
                .context("Failed to restore prebuilt sequencer database from dump")?;
            Vec::new()
        }
    };

    let config = config::sequencer_config(
        partial,
        temp_sequencer_dir.path().to_owned(),
        bedrock_addr,
        genesis_transactions,
        channel_id,
        cross_zone,
    )
    .context("Failed to create Sequencer config")?;

    let sequencer_handle = sequencer_service::run(config, 0).await?;

    Ok((sequencer_handle, temp_sequencer_dir))
}

pub fn setup_wallet(
    sequencer_addr: SocketAddr,
    initial_public_accounts: &[(PrivateKey, u128)],
    initial_private_accounts: &[InitialPrivateAccountForWallet],
    config_overrides: WalletConfigOverrides,
) -> Result<(WalletCore, TempDir, String)> {
    let config = config::wallet_config(sequencer_addr).context("Failed to create Wallet config")?;
    let config_serialized =
        serde_json::to_string_pretty(&config).context("Failed to serialize Wallet config")?;

    let temp_wallet_dir =
        tempfile::tempdir().context("Failed to create temp dir for wallet home")?;

    let config_path = temp_wallet_dir.path().join("wallet_config.json");
    std::fs::write(&config_path, config_serialized)
        .context("Failed to write wallet config in temp dir")?;

    let storage_path = temp_wallet_dir.path().join("storage.json");

    let wallet_password = "test_pass".to_owned();
    let (mut wallet, _mnemonic) = WalletCore::new_init_storage(
        config_path,
        storage_path,
        Some(config_overrides),
        &wallet_password,
    )
    .context("Failed to init wallet")?;

    for (private_key, _balance) in initial_public_accounts {
        wallet
            .storage_mut()
            .key_chain_mut()
            .add_imported_public_account(private_key.clone());
    }

    for private_account in initial_private_accounts {
        wallet
            .storage_mut()
            .key_chain_mut()
            .add_imported_private_account(
                private_account.key_chain.clone(),
                None,
                private_account.identifier,
                lee::Account::default(),
            );
    }

    wallet
        .store_persistent_data()
        .context("Failed to store wallet persistent data")?;

    Ok((wallet, temp_wallet_dir, wallet_password))
}

pub async fn setup_public_accounts_with_initial_supply(
    wallet: &mut WalletCore,
    initial_public_accounts: &[(PrivateKey, u128)],
) -> Result<()> {
    for (private_key, amount) in initial_public_accounts {
        let account_id =
            AccountId::for_public_key(PublicKey::new_from_private_key(private_key).value());
        wallet::cli::execute_subcommand(
            wallet,
            Command::Vault(VaultSubcommand::Claim {
                account_id: public_mention(account_id),
                amount: *amount,
            }),
        )
        .await
        .context("Failed to claim funds from vault into public account")?;
    }

    Ok(())
}

pub async fn setup_private_accounts_with_initial_supply(
    wallet: &mut WalletCore,
    initial_private_accounts: &[InitialPrivateAccountForWallet],
) -> Result<()> {
    for private_account in initial_private_accounts {
        claim_funds_from_vault_to_private(
            wallet,
            private_account.account_id(),
            private_account.balance,
        )
        .await
        .context("Failed to claim funds from vault into private account")?;
    }

    Ok(())
}

pub async fn sync_wallet_from_prebuilt(wallet: &mut WalletCore) -> Result<()> {
    wallet
        .sync_to_latest_block()
        .await
        .context("Failed to sync wallet from prebuilt chain")?;

    Ok(())
}

async fn claim_funds_from_vault_to_private(
    wallet: &mut WalletCore,
    owner_id: AccountId,
    amount: u128,
) -> Result<()> {
    let Some(_) = wallet.storage().key_chain().private_account(owner_id) else {
        bail!("Missing private account in wallet key chain for account {owner_id}");
    };

    let result = wallet::cli::execute_subcommand(
        wallet,
        Command::Vault(VaultSubcommand::Claim {
            account_id: private_mention(owner_id),
            amount,
        }),
    )
    .await
    .context("Failed to execute private vault claim command")?;

    let SubcommandReturnValue::TransactionExecuted { .. } = result else {
        bail!("Expected TransactionExecuted return value for private vault claim");
    };

    Ok(())
}
