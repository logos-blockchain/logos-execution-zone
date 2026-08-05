use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use indexer_service::{ChannelId, IndexerHandle};
use lee::{AccountId, PrivateKey, PublicKey};
use log::{debug, warn};
use sequencer_core::{
    block_publisher::ED25519_SECRET_KEY_SIZE,
    block_store::{DbDump, SequencerStore},
};
use sequencer_service::{GenesisAction, SequencerHandle};
use sequencer_service_rpc::{SequencerClient, SequencerClientBuilder};
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
    indexer_client::IndexerClient,
    private_mention, public_mention,
};

pub struct SequencerSetup {
    partial: config::SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    channel_id: ChannelId,
    genesis_transactions: Option<Vec<GenesisAction>>,
    cross_zone: Option<sequencer_core::config::CrossZoneConfig>,
    bedrock_signing_key: Option<[u8; ED25519_SECRET_KEY_SIZE]>,
}

impl SequencerSetup {
    #[must_use]
    pub fn new(partial: config::SequencerPartialConfig, bedrock_addr: SocketAddr) -> Self {
        Self {
            partial,
            bedrock_addr,
            channel_id: config::bedrock_channel_id(),
            genesis_transactions: None,
            cross_zone: None,
            bedrock_signing_key: None,
        }
    }

    /// Set the Bedrock channel ID to use for the sequencer.
    /// If not set, the default channel ID from the Bedrock config will be used.
    #[must_use]
    pub const fn with_channel_id(mut self, channel_id: ChannelId) -> Self {
        self.channel_id = channel_id;
        self
    }

    /// Set the cross-zone configuration to use for the sequencer.
    /// If not set, the sequencer will be configured to run in single-zone mode.
    #[must_use]
    pub fn with_cross_zone(mut self, cross_zone: sequencer_core::config::CrossZoneConfig) -> Self {
        self.cross_zone = Some(cross_zone);
        self
    }

    /// Set the genesis transactions to apply when initializing the sequencer.
    /// If not set, the sequencer will be initialized from a prebuilt database dump.
    #[must_use]
    pub fn with_genesis(mut self, genesis_transactions: Vec<GenesisAction>) -> Self {
        self.genesis_transactions = Some(genesis_transactions);
        self
    }

    /// Pre-write a bedrock (Ed25519, 32-byte seed) signing key into the home
    /// before boot, so tests know the sequencer's public key in advance (e.g.
    /// to accredit a committee member that has not started yet).
    #[must_use]
    pub const fn with_bedrock_signing_key(mut self, key: [u8; ED25519_SECRET_KEY_SIZE]) -> Self {
        self.bedrock_signing_key = Some(key);
        self
    }

    /// Set up the sequencer in a fresh temporary home directory, returning the
    /// owning [`TempDir`] alongside the handle.
    pub async fn setup(self) -> Result<(SequencerHandle, TempDir)> {
        let temp_sequencer_dir =
            tempfile::tempdir().context("Failed to create temp dir for sequencer home")?;

        let sequencer_handle = self.setup_at(temp_sequencer_dir.path()).await?;

        Ok((sequencer_handle, temp_sequencer_dir))
    }

    /// Set up the sequencer in an explicit home directory owned by the caller.
    pub async fn setup_in(self, home: &Path) -> Result<SequencerHandle> {
        std::fs::create_dir_all(home).context("Failed to create sequencer home")?;
        self.setup_at(home).await
    }

    /// Set up the sequencer in an explicit `home` directory owned by the caller.
    ///
    /// Useful for tests that restart the sequencer against the same on-disk store.
    pub async fn setup_at(self, home: &Path) -> Result<SequencerHandle> {
        let Self {
            partial,
            bedrock_addr,
            channel_id,
            genesis_transactions,
            cross_zone,
            bedrock_signing_key,
        } = self;

        debug!("Using sequencer home at {}", home.display());

        if let Some(key_bytes) = bedrock_signing_key {
            std::fs::write(home.join("bedrock_signing_key"), key_bytes)
                .context("Failed to write pre-generated bedrock signing key")?;
        }

        let genesis_transactions = if let Some(genesis) = genesis_transactions {
            genesis
        } else {
            let dump = load_prebuilt_dump()?;
            // `SequencerCore::open_or_create_store` looks for `<home>/rocksdb`.
            let dst = home.join("rocksdb");
            let _store = SequencerStore::restore_db_from_dump(
                &dst,
                &dump,
                lee::PrivateKey::try_new(config::SEQUENCER_SIGNING_KEY)?,
            )
            .context("Failed to restore prebuilt sequencer database from dump")?;
            // TODO: Technically not correct, we should reconstruct the genesis transactions
            // from the dump, but this crutch doesn't affect anything for now
            Vec::new()
        };

        let config = config::sequencer_config(
            partial,
            home.to_owned(),
            bedrock_addr,
            channel_id,
            config::bedrock_funding_key(),
            genesis_transactions,
            cross_zone,
        )
        .context("Failed to create Sequencer config")?;

        sequencer_service::run(config, SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("Failed to run Sequencer Service")
    }
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

/// Builds an HTTP RPC client for the sequencer at `addr`.
pub fn sequencer_client(addr: SocketAddr) -> Result<SequencerClient> {
    let url = config::addr_to_url(config::UrlProtocol::Http, addr)
        .context("Failed to build sequencer URL")?;
    SequencerClientBuilder::default()
        .build(url)
        .context("Failed to build sequencer client")
}

/// Builds a WebSocket RPC client for the indexer at `addr`.
pub async fn indexer_client(addr: SocketAddr) -> Result<IndexerClient> {
    let url = config::addr_to_url(config::UrlProtocol::Ws, addr)
        .context("Failed to build indexer URL")?;
    IndexerClient::new(&url)
        .await
        .context("Failed to build indexer client")
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

    let handle = setup_indexer_at(
        bedrock_addr,
        channel_id,
        cross_zone,
        temp_indexer_dir.path(),
    )
    .await?;

    Ok((handle, temp_indexer_dir))
}

/// Set up the indexer in an explicit home directory owned by the caller.
pub async fn setup_indexer_at(
    bedrock_addr: SocketAddr,
    channel_id: ChannelId,
    cross_zone: Option<sequencer_core::config::CrossZoneConfig>,
    home: &Path,
) -> Result<IndexerHandle> {
    std::fs::create_dir_all(home).context("Failed to create indexer home")?;

    debug!("Using indexer home at {}", home.display());

    let indexer_config = config::indexer_config(bedrock_addr, channel_id, cross_zone)
        .context("Failed to create Indexer config")?;

    indexer_service::run_server(
        indexer_config,
        home,
        0,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .context("Failed to run Indexer Service")
}

pub async fn setup_wallet(
    sequencer_addr: SocketAddr,
    initial_public_accounts: &[(PrivateKey, u128)],
    initial_private_accounts: &[InitialPrivateAccountForWallet],
    config_overrides: WalletConfigOverrides,
) -> Result<(WalletCore, TempDir, String)> {
    let temp_wallet_dir =
        tempfile::tempdir().context("Failed to create temp dir for wallet home")?;
    let (wallet, _state_dir, password) = setup_wallet_at(
        sequencer_addr,
        initial_public_accounts,
        initial_private_accounts,
        config_overrides,
        temp_wallet_dir.path(),
    )
    .await?;

    Ok((wallet, temp_wallet_dir, password))
}

/// Set up the wallet in an explicit home directory owned by the caller.
pub async fn setup_wallet_at(
    sequencer_addr: SocketAddr,
    initial_public_accounts: &[(PrivateKey, u128)],
    initial_private_accounts: &[InitialPrivateAccountForWallet],
    config_overrides: WalletConfigOverrides,
    home: &Path,
) -> Result<(WalletCore, PathBuf, String)> {
    let config = config::wallet_config(sequencer_addr).context("Failed to create Wallet config")?;
    let config_serialized =
        serde_json::to_string_pretty(&config).context("Failed to serialize Wallet config")?;

    std::fs::create_dir_all(home).context("Failed to create wallet home")?;

    let config_path = home.join("wallet_config.json");
    std::fs::write(&config_path, config_serialized).context("Failed to write wallet config")?;

    let storage_path = home.join("storage.json");
    let metrics_path = home.join("metrics.json");

    let wallet_password = "test_pass".to_owned();
    let (mut wallet, _mnemonic) = WalletCore::new_init_storage(
        config_path,
        storage_path,
        metrics_path,
        Some(config_overrides),
        &wallet_password,
    )
    .await
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

    Ok((wallet, home.to_owned(), wallet_password))
}

pub async fn setup_public_accounts_with_initial_supply(
    wallet: &mut WalletCore,
    initial_public_accounts: &[(PrivateKey, u128)],
) -> Result<()> {
    setup_public_accounts_with_initial_supply_owned(wallet, initial_public_accounts.to_vec()).await
}

async fn setup_public_accounts_with_initial_supply_owned(
    wallet: &mut WalletCore,
    initial_public_accounts: Vec<(PrivateKey, u128)>,
) -> Result<()> {
    for (private_key, amount) in initial_public_accounts {
        let account_id = AccountId::from(&PublicKey::new_from_private_key(&private_key));
        wallet::cli::execute_subcommand(
            wallet,
            Command::Vault(VaultSubcommand::Claim {
                account_id: public_mention(account_id),
                amount,
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

pub fn initialize_wallet_public_accounts(
    mut wallet: WalletCore,
    initial_public_accounts: Vec<(PrivateKey, u128)>,
) -> Result<WalletCore> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create wallet initialization runtime")?;

    runtime.block_on(async move {
        setup_public_accounts_with_initial_supply_owned(&mut wallet, initial_public_accounts)
            .await?;
        Ok(wallet)
    })
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
