//! Shared test/bench fixtures: spins up bedrock + sequencer + indexer + wallet
//! end-to-end against docker-compose, exposes a `TestContext` callers can drive.

use std::{collections::HashMap, net::SocketAddr, path::Path, sync::LazyLock};

use anyhow::{Context as _, Result};
use common::{HashType, transaction::LeeTransaction};
use futures::FutureExt as _;
use indexer_service::{ChannelId, IndexerHandle};
use lee::{AccountId, PrivacyPreservingTransaction, PrivateKey};
use lee_core::Commitment;
use log::{debug, error};
use sequencer_core::{
    block_publisher::{Ed25519Key, post_channel_config},
    config::GenesisAction,
};
use sequencer_service::{
    BedrockConfig, CrossZoneConfig, GossipConfig, SequencerHandle, default_priority_fee,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use serde::Serialize;
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{
    WalletCore, account::AccountIdWithPrivacy, cli::CliAccountMention,
    config::WalletConfigOverrides,
};

use crate::{
    config::{
        InitialPrivateAccountForWallet, MultiNodeTestContextConfig, SequencerPartialConfig,
        bedrock_funding_key,
    },
    indexer_client::IndexerClient,
    setup::{
        SequencerSetup, setup_bedrock_node, setup_indexer,
        setup_private_accounts_with_initial_supply, setup_public_accounts_with_initial_supply,
        setup_wallet, sync_wallet_from_prebuilt,
    },
};

pub mod config;
pub mod indexer_client;
pub mod setup;

// TODO: Remove this and control time from tests
pub const TIME_TO_WAIT_FOR_BLOCK_SECONDS: u64 = 12;
/// 1 s bedrock slots: rotate the turn every ~20 s of tenure; steal a stalled
/// turn after ~30 s (bounds the stall while B is accredited but not started).
const POSTING_TIMEFRAME_SLOTS: u32 = 20;
const POSTING_TIMEOUT_SLOTS: u32 = 30;

pub(crate) const BEDROCK_SERVICE_WITH_OPEN_PORT: &str = "logos-blockchain-node-0";
pub(crate) const BEDROCK_SERVICE_PORT: u16 = 18080;

static LOGGER: LazyLock<()> = LazyLock::new(env_logger::init);

struct IndexerComponents {
    indexer_handle: IndexerHandle,
    indexer_client: IndexerClient,
    temp_dir: TempDir,
}

impl Drop for IndexerComponents {
    fn drop(&mut self) {
        let Self {
            indexer_handle,
            indexer_client: _,
            temp_dir: _,
        } = self;

        if !indexer_handle.is_healthy() {
            error!("Indexer handle has unexpectedly stopped before IndexerComponents drop");
        }
    }
}

/// Recursively-sized bytes on disk for sequencer / indexer / wallet tempdirs.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct DiskSizes {
    pub sequencer_bytes: u64,
    pub indexer_bytes: u64,
    pub wallet_bytes: u64,
}

pub struct SequencerComponents {
    pub sequencer_handle: SequencerHandle,
    pub temp_sequencer_dir: TempDir,
    pub sequencer_client: SequencerClient,
}

pub struct WalletComponents {
    wallet: WalletCore,
    wallet_password: String,
    temp_wallet_dir: TempDir,
}

pub struct TestContextZone {
    wallet: Option<WalletComponents>,
    /// Order of sequencers matter, as first one starts a channel, other ones connect in order.
    sequencers: Vec<SequencerComponents>,
    indexer: Option<IndexerComponents>,
}

/// Test context which sets up a sequencer and a wallet for integration tests.
///
/// It's memory and logically safe to create multiple instances of this struct in parallel tests,
/// as each instance uses its own temporary directories for sequencer and wallet data.
pub struct TestContext {
    zones: HashMap<ChannelId, TestContextZone>,
    bedrock_compose: DockerCompose,
    bedrock_addr: SocketAddr,
}

impl TestContext {
    /// Create new test context with singular config(1 zone, 1 sequencer).
    pub async fn new() -> Result<Self> {
        MultiZoneTestContextBuilder::default()
            .with_zone(ZoneTestContextBuilder::new(
                MultiNodeTestContextConfig::default(),
            ))
            .build()
            .await
    }

    /// Reference for the default zone(in case if only one present).
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn default_zone(&self) -> &TestContextZone {
        assert!(self.zones.len() == 1);

        self.zones
            .values()
            .next()
            .expect("Must be at least one zone")
    }

    /// Reference for the default sequencer component(in case, if only one zone exists and only
    /// one sequencer exists).
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn default_sequencer_component(&self) -> &SequencerComponents {
        self.default_zone()
            .sequencers
            .first()
            .expect("Must be at least one sequencer component")
    }

    /// Iterator over all zones in random order.
    pub fn zones_iter(&self) -> impl Iterator<Item = (&ChannelId, &TestContextZone)> {
        self.zones.iter()
    }

    /// Iterator over all sequencer components in zone in order.
    #[must_use]
    pub fn sequencer_components_iter(
        &self,
        channel_id: ChannelId,
    ) -> Option<impl Iterator<Item = &SequencerComponents>> {
        self.zones
            .get(&channel_id)
            .map(|zone| zone.sequencers.iter())
    }

    /// Reference for the default sequencer component for a zone (in case, if only one sequencer
    /// exists).
    #[must_use]
    pub fn zone_default_sequencer_component(&self, channel_id: ChannelId) -> &SequencerComponents {
        self.sequencer_components_iter(channel_id)
            .unwrap()
            .next()
            .unwrap()
    }

    /// Mutable reference for the default zone(in case if only one present).
    ///
    /// Panics in case if there is more than one zone.
    pub fn default_zone_mut(&mut self) -> &mut TestContextZone {
        assert!(self.zones.len() == 1);

        self.zones
            .values_mut()
            .next()
            .expect("Must be at least one zone")
    }

    /// Mutable reference for the default sequencer component(in case, if only one zone exists and
    /// only one sequencer exists).
    ///
    /// Panics in case if there is more than one zone.
    pub fn default_sequencer_component_mut(&mut self) -> &mut SequencerComponents {
        self.default_zone_mut()
            .sequencers
            .iter_mut()
            .next()
            .expect("Must be at least one integration component")
    }

    /// Get reference to the default wallet.
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn wallet(&self) -> &WalletCore {
        &self.default_zone().wallet.as_ref().unwrap().wallet
    }

    /// Get password of the default wallet password.
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn wallet_password(&self) -> &str {
        &self.default_zone().wallet.as_ref().unwrap().wallet_password
    }

    /// Get mutable reference to default the wallet.
    ///
    /// Panics in case if there is more than one zone.
    pub fn wallet_mut(&mut self) -> &mut WalletCore {
        &mut self.default_zone_mut().wallet.as_mut().unwrap().wallet
    }

    /// Get reference to the zone wallet.
    #[must_use]
    pub fn wallet_zone(&self, channel_id: ChannelId) -> Option<&WalletCore> {
        self.zones
            .get(&channel_id)
            .map(|val| &val.wallet.as_ref().unwrap().wallet)
    }

    /// Get password of the zone wallet.
    #[must_use]
    pub fn wallet_password_zone(&self, channel_id: ChannelId) -> Option<&str> {
        self.zones
            .get(&channel_id)
            .map(|val| val.wallet.as_ref().unwrap().wallet_password.as_str())
    }

    /// Get mutable reference to the zone wallet.
    pub fn wallet_mut_zone(&mut self, channel_id: ChannelId) -> Option<&mut WalletCore> {
        self.zones
            .get_mut(&channel_id)
            .map(|val| &mut val.wallet.as_mut().unwrap().wallet)
    }

    /// Get reference to the sequencer client in default case (1 zone, 1 sequencer).
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn sequencer_client(&self) -> &SequencerClient {
        &self.default_sequencer_component().sequencer_client
    }

    /// Get reference to the sequencer client by node zone `channel_id` and its `id`.
    #[must_use]
    pub fn sequencer_client_by_node_ids(
        &self,
        channel_id: ChannelId,
        id: usize,
    ) -> Option<&SequencerClient> {
        let val = self.zones.get(&channel_id)?;
        val.sequencers.get(id).map(|vall| &vall.sequencer_client)
    }

    /// Get the Bedrock Node address.
    #[must_use]
    pub const fn bedrock_addr(&self) -> SocketAddr {
        self.bedrock_addr
    }

    /// Get reference to the default indexer(1 zone).
    ///
    /// # Panics
    ///
    /// Panics if the indexer is not enabled in the test context. See
    /// [`ZoneTestContextBuilder::disable_indexer()`].
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn indexer(&self) -> &IndexerHandle {
        &self
            .default_zone()
            .indexer
            .as_ref()
            .expect("Called `TestContext::indexer()` on context with disabled indexer")
            .indexer_handle
    }

    /// Get the default indexer's(1 zone) bound socket address.
    ///
    /// # Panics
    ///
    /// Panics if the indexer is not enabled in the test context.
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn indexer_addr(&self) -> SocketAddr {
        self.indexer().addr()
    }

    /// Get reference to the default indexer(1 zone) client.
    ///
    /// # Panics
    ///
    /// Panics if the indexer is not enabled in the test context. See
    /// [`ZoneTestContextBuilder::disable_indexer()`].
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn indexer_client(&self) -> &IndexerClient {
        &self
            .default_zone()
            .indexer
            .as_ref()
            .expect("Called `TestContext::indexer()` on context with disabled indexer")
            .indexer_client
    }

    /// Get reference to the indexer for corresponding zone.
    ///
    /// # Panics
    ///
    /// Panics if the indexer is not enabled in the test context. See
    /// [`ZoneTestContextBuilder::disable_indexer()`].
    #[must_use]
    pub fn indexer_zone(&self, channel_id: ChannelId) -> Option<&IndexerHandle> {
        let val = self.zones.get(&channel_id)?;
        val.indexer.as_ref().map(|val| &val.indexer_handle)
    }

    /// Get the default indexer's bound socket address for corresponding zone.
    ///
    /// # Panics
    ///
    /// Panics if the indexer is not enabled in the test context.
    #[must_use]
    pub fn indexer_addr_zone(&self, channel_id: ChannelId) -> Option<SocketAddr> {
        self.indexer_zone(channel_id)
            .map(indexer_service::IndexerHandle::addr)
    }

    /// Get reference to the indexer client for corresponding zone.
    ///
    /// # Panics
    ///
    /// Panics if the indexer is not enabled in the test context. See
    /// [`ZoneTestContextBuilder::disable_indexer()`].
    #[must_use]
    pub fn indexer_client_zone(&self, channel_id: ChannelId) -> Option<&IndexerClient> {
        let val = self.zones.get(&channel_id)?;
        val.indexer.as_ref().map(|val| &val.indexer_client)
    }

    /// Recursively-sized bytes on disk for sequencer + indexer + wallet tempdirs.
    /// Indexer bytes are zero if the indexer is disabled.
    /// Wallet bytes are zero if the wallet is disabled.
    #[must_use]
    pub fn disk_sizes(&self) -> DiskSizes {
        DiskSizes {
            sequencer_bytes: self.zones.values().fold(0, |acc, zone| {
                acc.saturating_add(zone.sequencers.iter().fold(0, |accc, component| {
                    accc.saturating_add(dir_size_bytes(component.temp_sequencer_dir.path()))
                }))
            }),
            indexer_bytes: self.zones.values().fold(0, |acc, zone| {
                acc.saturating_add(
                    zone.indexer
                        .as_ref()
                        .map_or(0, |val| dir_size_bytes(val.temp_dir.path())),
                )
            }),
            wallet_bytes: self.zones.values().fold(0, |acc, zone| {
                acc.saturating_add(
                    zone.wallet
                        .as_ref()
                        .map_or(0, |val| dir_size_bytes(val.temp_wallet_dir.path())),
                )
            }),
        }
    }

    /// Get default(1 zone) existing public account IDs in the wallet.
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn existing_public_accounts(&self) -> Vec<AccountId> {
        self.default_zone()
            .wallet
            .as_ref()
            .unwrap()
            .wallet
            .storage()
            .key_chain()
            .public_account_ids()
            .map(|(account_id, _idx)| account_id)
            .collect()
    }

    /// Get default (1 zone) existing private account IDs in the wallet.
    ///
    /// Panics in case if there is more than one zone.
    #[must_use]
    pub fn existing_private_accounts(&self) -> Vec<AccountId> {
        self.default_zone()
            .wallet
            .as_ref()
            .unwrap()
            .wallet
            .storage()
            .key_chain()
            .private_account_ids()
            .map(|(account_id, _idx)| account_id)
            .collect()
    }

    /// Get existing public account IDs in the wallet.
    #[must_use]
    pub fn existing_public_accounts_zone(&self, channel_id: ChannelId) -> Option<Vec<AccountId>> {
        self.wallet_zone(channel_id).map(|wallet_ref| {
            wallet_ref
                .storage()
                .key_chain()
                .public_account_ids()
                .map(|(account_id, _idx)| account_id)
                .collect()
        })
    }

    /// Get existing private account IDs in the wallet.
    #[must_use]
    pub fn existing_private_accounts_zone(&self, channel_id: ChannelId) -> Option<Vec<AccountId>> {
        self.wallet_zone(channel_id).map(|wallet_ref| {
            wallet_ref
                .storage()
                .key_chain()
                .private_account_ids()
                .map(|(account_id, _idx)| account_id)
                .collect()
        })
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let Self {
            zones,
            bedrock_compose,
            bedrock_addr: _,
        } = self;

        #[expect(
            clippy::iter_over_hash_type,
            reason = "Zones can be stopped in any order"
        )]
        for TestContextZone {
            wallet: _,
            sequencers,
            indexer: _,
        } in zones.values_mut()
        {
            for SequencerComponents {
                sequencer_handle,
                temp_sequencer_dir: _,
                sequencer_client: _,
            } in sequencers.iter_mut()
            {
                if !sequencer_handle.is_healthy() {
                    let Err(err) = sequencer_handle
                        .failed()
                        .now_or_never()
                        .expect("Sequencer handle should not be running");
                    error!(
                        "Sequencer handle has unexpectedly stopped before TestContext drop with error: {err:#}"
                    );
                }
            }
        }

        let container = bedrock_compose
            .service(BEDROCK_SERVICE_WITH_OPEN_PORT)
            .unwrap_or_else(|| {
                panic!("Failed to get Bedrock service container `{BEDROCK_SERVICE_WITH_OPEN_PORT}`")
            });
        let output = std::process::Command::new("docker")
            .args(["inspect", "-f",  "{{.State.Running}}", container.id()])
            .output()
            .expect("Failed to execute docker inspect command to check if Bedrock container is still running");
        let stdout = String::from_utf8(output.stdout)
            .expect("Failed to parse docker inspect output as String");
        if stdout.trim() != "true" {
            error!(
                "Bedrock container `{}` is not running during TestContext drop, docker inspect output: {stdout}",
                container.id()
            );
        }
    }
}

#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "test-context builder toggles independent features; a state machine would obscure it"
)]
pub struct ZoneTestContextBuilder {
    genesis_transactions: Option<Vec<GenesisAction>>,
    sequencer_partial_config: Option<config::SequencerPartialConfig>,
    follower_sequencer_partial_config: Option<config::SequencerPartialConfig>,
    enable_indexer: bool,
    enable_wallet: bool,
    enable_gossip: bool,
    wallet_config_overrides: WalletConfigOverrides,
    from_scratch: bool,
    mn_config: MultiNodeTestContextConfig,
    cross_zone_config: Option<CrossZoneConfig>,
}

impl ZoneTestContextBuilder {
    #[must_use]
    pub fn new(mn_config: MultiNodeTestContextConfig) -> Self {
        Self {
            genesis_transactions: None,
            sequencer_partial_config: None,
            follower_sequencer_partial_config: None,
            enable_indexer: true,
            enable_wallet: true,
            enable_gossip: false,
            wallet_config_overrides: WalletConfigOverrides::default(),
            from_scratch: false,
            mn_config,
            // There is no point providing cross zone config here, it is easier to provide it from
            // builder pattern.
            cross_zone_config: None,
        }
    }

    #[must_use]
    pub const fn bedrock_channel(&self) -> ChannelId {
        self.mn_config.bedrock_channel
    }

    /// Override wallet config fields (e.g. polling timeouts) for the wallet built by this context.
    #[must_use]
    pub fn with_wallet_config_overrides(
        mut self,
        wallet_config_overrides: WalletConfigOverrides,
    ) -> Self {
        self.wallet_config_overrides = wallet_config_overrides;
        self
    }

    /// Set the genesis transactions to apply when initializing the sequencer.
    /// If not set, the sequencer will be initialized from a prebuilt database dump.
    #[must_use]
    pub fn with_genesis(mut self, genesis_transactions: Vec<GenesisAction>) -> Self {
        self.genesis_transactions = Some(genesis_transactions);
        self
    }

    /// Set the sequencer partial config to apply when initializing the sequencer.
    /// If not set, the sequencer will be initialized with default one.
    #[must_use]
    pub const fn with_sequencer_partial_config(
        mut self,
        sequencer_partial_config: config::SequencerPartialConfig,
    ) -> Self {
        self.sequencer_partial_config = Some(sequencer_partial_config);
        self
    }

    /// Override the sequencer partial config for the non-leader nodes only.
    /// If not set, followers use the same config as the leader.
    #[must_use]
    pub const fn with_follower_sequencer_partial_config(
        mut self,
        follower_sequencer_partial_config: config::SequencerPartialConfig,
    ) -> Self {
        self.follower_sequencer_partial_config = Some(follower_sequencer_partial_config);
        self
    }

    /// Enable p2p gossip between the sequencers: the leader listens on an
    /// OS-assigned localhost port and every follower bootstraps from it.
    #[must_use]
    pub const fn with_gossip(mut self) -> Self {
        self.enable_gossip = true;
        self
    }

    /// Build from genesis live instead of loading the prebuilt fixture. Implied by
    /// [`Self::with_genesis`].
    #[must_use]
    pub const fn from_scratch(mut self) -> Self {
        self.from_scratch = true;
        self
    }

    /// Exclude Indexer from test context.
    /// Indexer is enabled by default.
    ///
    /// Methods like [`TestContext::indexer()`] and [`TestContext::indexer_client()`] will panic if
    /// called when indexer is disabled.
    #[must_use]
    pub const fn disable_indexer(mut self) -> Self {
        self.enable_indexer = false;
        self
    }

    /// Exclude wallet from test context.
    /// Wallet is enabled by default.
    ///
    /// Methods like [`TestContext::wallet()`] will panic if
    /// called when wallet is disabled.
    #[must_use]
    pub const fn disable_wallet(mut self) -> Self {
        self.enable_wallet = false;
        self
    }

    /// Set the cross zone config to apply when initializing the zone.
    /// If not set, the zone will be initialized with default one.
    #[must_use]
    pub fn with_cross_zone(mut self, cross_zone_config: Option<CrossZoneConfig>) -> Self {
        self.cross_zone_config = cross_zone_config;
        self
    }

    pub async fn build(self, bedrock_addr: SocketAddr) -> Result<TestContextZone> {
        let Self {
            genesis_transactions,
            sequencer_partial_config,
            follower_sequencer_partial_config,
            enable_indexer,
            enable_wallet,
            enable_gossip,
            wallet_config_overrides,
            from_scratch,
            mn_config,
            cross_zone_config,
        } = self;

        debug!("Test context setup");

        // The fixture bakes in the default accounts + genesis, so custom genesis / from_scratch
        // must build live. Otherwise load the fixture (fails if it is missing).
        let use_prebuilt = !from_scratch && genesis_transactions.is_none();

        let indexer_components = if enable_indexer {
            let (indexer_handle, temp_indexer_dir) = setup_indexer(
                bedrock_addr,
                mn_config.bedrock_channel,
                cross_zone_config.clone(),
            )
            .await
            .context("Failed to setup Indexer")?;
            let indexer_client = setup::indexer_client(indexer_handle.addr())
                .await
                .context("Failed to create indexer client")?;
            Some(IndexerComponents {
                indexer_handle,
                indexer_client,
                temp_dir: temp_indexer_dir,
            })
        } else {
            None
        };

        let initial_public_accounts = config::default_public_accounts_for_wallet();
        let initial_private_accounts = config::default_private_accounts_for_wallet();

        let partial_config = sequencer_partial_config.unwrap_or_default();

        let mut sequencer_addrs = vec![];
        let mut sequencer_components = vec![];

        let mut sequencer_keys = vec![];

        sequencer_keys.push(config::SEQUENCER_SIGNING_KEY);

        sequencer_keys.extend((1..mn_config.num_nodes).map(|i| {
            config::sequencer_signing_key_from_seed(
                u32::try_from(i).expect("Not being able to fit is realistically impossible"),
            )
        }));

        // First, need to start a leader.
        let leader_gossip = enable_gossip.then(|| GossipConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("hardcoded gossip listen multiaddr is valid"),
            bootstrap_peers: vec![],
        });
        let (leader_addr, leader_components) = build_sequencer_components(
            partial_config,
            bedrock_addr,
            enable_wallet,
            use_prebuilt,
            &initial_public_accounts,
            &initial_private_accounts,
            genesis_transactions.clone(),
            config::SEQUENCER_SIGNING_KEY,
            mn_config.bedrock_channel,
            cross_zone_config.clone(),
            leader_gossip,
        )
        .await?;

        // The leader listened on an OS-assigned port, so followers can only
        // learn its gossip address from the running handle.
        let follower_gossip = leader_components
            .sequencer_handle
            .gossip_bootstrap_addrs()
            .map(|bootstrap_peers| GossipConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("hardcoded gossip listen multiaddr is valid"),
                bootstrap_peers,
            });

        // Wait for genesis to be published
        wait_until_genesis(&leader_components.sequencer_client)
            .await
            .context("Encountered an error while waiting for genesis to be published")?;

        log::info!("Passed wait untill genesis");

        sequencer_addrs.push(leader_addr);
        sequencer_components.push(leader_components);

        // Skip posting chain config with just one node.
        if mn_config.num_nodes != 1 {
            post_chain_config_with_default_parameters(
                mn_config.bedrock_channel,
                bedrock_addr,
                sequencer_keys.clone(),
            )
            .await?;
        }

        for sequencer_key in sequencer_keys.into_iter().skip(1) {
            let (sequencer_addr, sequencer_component) = build_sequencer_components(
                follower_sequencer_partial_config.unwrap_or(partial_config),
                bedrock_addr,
                enable_wallet,
                use_prebuilt,
                &initial_public_accounts,
                &initial_private_accounts,
                genesis_transactions.clone(),
                sequencer_key,
                mn_config.bedrock_channel,
                cross_zone_config.clone(),
                follower_gossip.clone(),
            )
            .await?;

            sequencer_addrs.push(sequencer_addr);
            sequencer_components.push(sequencer_component);
        }

        let wallet_components = if enable_wallet {
            let (mut wallet, temp_wallet_dir, wallet_password) = setup_wallet(
                &sequencer_addrs,
                &initial_public_accounts,
                &initial_private_accounts,
                wallet_config_overrides,
            )
            .await
            .context("Failed to setup wallet")?;

            if use_prebuilt {
                // Funds already exist on-chain in the prebuilt blocks; sync instead of
                // claiming live.
                sync_wallet_from_prebuilt(&mut wallet)
                    .await
                    .context("Failed to sync wallet from prebuilt database")?;
            } else {
                setup_public_accounts_with_initial_supply(&mut wallet, &initial_public_accounts)
                    .await
                    .context("Failed to initialize public accounts in wallet")?;

                setup_private_accounts_with_initial_supply(&mut wallet, &initial_private_accounts)
                    .await
                    .context("Failed to initialize private accounts in wallet")?;
            }

            Some(WalletComponents {
                wallet,
                wallet_password,
                temp_wallet_dir,
            })
        } else {
            None
        };

        Ok(TestContextZone {
            wallet: wallet_components,
            sequencers: sequencer_components,
            indexer: indexer_components,
        })
    }

    pub fn build_blocking(self, bedrock_addr: SocketAddr) -> Result<BlockingTestContextZone> {
        let runtime = tokio::runtime::Runtime::new().context("Failed to create Tokio runtime")?;

        let ctx = runtime.block_on(self.build(bedrock_addr))?;

        Ok(BlockingTestContextZone {
            ctx: Some(ctx),
            runtime,
        })
    }
}

#[derive(Default)]
pub struct MultiZoneTestContextBuilder {
    zone_builders: HashMap<ChannelId, ZoneTestContextBuilder>,
}

impl MultiZoneTestContextBuilder {
    pub async fn build(self) -> Result<TestContext> {
        // Ensure logger is initialized only once
        *LOGGER;

        let (bedrock_compose, bedrock_addr) = setup_bedrock_node()
            .await
            .context("Failed to setup Bedrock node")?;

        let mut zones = HashMap::new();

        #[expect(
            clippy::iter_over_hash_type,
            reason = "Zones can be started in any order"
        )]
        for (channel_id, zone_builder) in self.zone_builders {
            let zone_ctx = zone_builder.build(bedrock_addr).await?;

            log::info!("Built context for {channel_id}");

            zones.insert(channel_id, zone_ctx);
        }

        Ok(TestContext {
            zones,
            bedrock_compose,
            bedrock_addr,
        })
    }

    #[must_use]
    pub fn with_zone(mut self, zone_builder: ZoneTestContextBuilder) -> Self {
        assert!(
            !self
                .zone_builders
                .contains_key(&zone_builder.bedrock_channel())
        );

        self.zone_builders
            .insert(zone_builder.bedrock_channel(), zone_builder);

        self
    }

    #[must_use]
    pub fn default_channel_id(&self) -> ChannelId {
        *self
            .zone_builders
            .keys()
            .next()
            .expect("Must be at least one channel")
    }

    pub fn build_blocking(self) -> Result<BlockingTestContext> {
        let runtime = tokio::runtime::Runtime::new().context("Failed to create Tokio runtime")?;

        let ctx = runtime.block_on(self.build())?;

        Ok(BlockingTestContext {
            ctx: Some(ctx),
            runtime,
        })
    }
}

/// A test context to be used in normal #[test] tests.
pub struct BlockingTestContextZone {
    ctx: Option<TestContextZone>,
    runtime: tokio::runtime::Runtime,
}

impl BlockingTestContextZone {
    pub fn new(config: MultiNodeTestContextConfig, bedrock_addr: SocketAddr) -> Result<Self> {
        ZoneTestContextBuilder::new(config).build_blocking(bedrock_addr)
    }

    pub const fn ctx(&self) -> &TestContextZone {
        self.ctx.as_ref().expect("TestContext is set")
    }

    pub const fn ctx_mut(&mut self) -> &mut TestContextZone {
        self.ctx.as_mut().expect("TestContext is set")
    }

    pub const fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }

    pub fn block_on<'ctx, F>(&'ctx self, f: impl FnOnce(&'ctx TestContextZone) -> F) -> F::Output
    where
        F: std::future::Future + 'ctx,
    {
        let future = f(self.ctx());
        self.runtime.block_on(future)
    }

    pub fn block_on_mut<'ctx, F>(
        &'ctx mut self,
        f: impl FnOnce(&'ctx mut TestContextZone) -> F,
    ) -> F::Output
    where
        F: std::future::Future + 'ctx,
    {
        let ctx_mut = self.ctx.as_mut().expect("TestContext is set");
        let future = f(ctx_mut);
        self.runtime.block_on(future)
    }
}

impl Drop for BlockingTestContextZone {
    fn drop(&mut self) {
        let Self { ctx, runtime } = self;

        // Ensure async cleanup of TestContext by blocking on its drop in the runtime.
        runtime.block_on(async {
            if let Some(ctx) = ctx.take() {
                drop(ctx);
            }
        });
    }
}

/// A test context to be used in normal #[test] tests.
pub struct BlockingTestContext {
    ctx: Option<TestContext>,
    runtime: tokio::runtime::Runtime,
}

impl BlockingTestContext {
    /// For now, only one zone and one sequencer is supported for blocking operations.
    pub fn new_default() -> Result<Self> {
        let mut zone_builders = HashMap::new();

        zone_builders.insert(
            config::bedrock_channel_id(),
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default()),
        );

        MultiZoneTestContextBuilder { zone_builders }.build_blocking()
    }

    pub const fn ctx(&self) -> &TestContext {
        self.ctx.as_ref().expect("TestContext is set")
    }

    pub const fn ctx_mut(&mut self) -> &mut TestContext {
        self.ctx.as_mut().expect("TestContext is set")
    }

    pub const fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }

    pub fn block_on<'ctx, F>(&'ctx self, f: impl FnOnce(&'ctx TestContext) -> F) -> F::Output
    where
        F: std::future::Future + 'ctx,
    {
        let future = f(self.ctx());
        self.runtime.block_on(future)
    }

    pub fn block_on_mut<'ctx, F>(
        &'ctx mut self,
        f: impl FnOnce(&'ctx mut TestContext) -> F,
    ) -> F::Output
    where
        F: std::future::Future + 'ctx,
    {
        let ctx_mut = self.ctx.as_mut().expect("TestContext is set");
        let future = f(ctx_mut);
        self.runtime.block_on(future)
    }
}

impl Drop for BlockingTestContext {
    fn drop(&mut self) {
        let Self { ctx, runtime } = self;

        // Ensure async cleanup of TestContext by blocking on its drop in the runtime.
        runtime.block_on(async {
            if let Some(ctx) = ctx.take() {
                drop(ctx);
            }
        });
    }
}

#[must_use]
pub const fn public_mention(account_id: AccountId) -> CliAccountMention {
    CliAccountMention::Id(AccountIdWithPrivacy::Public(account_id))
}

#[must_use]
pub const fn private_mention(account_id: AccountId) -> CliAccountMention {
    CliAccountMention::Id(AccountIdWithPrivacy::Private(account_id))
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "We want the code to panic if the transaction type is not PrivacyPreserving"
)]
pub async fn fetch_privacy_preserving_tx(
    seq_client: &SequencerClient,
    tx_hash: HashType,
) -> PrivacyPreservingTransaction {
    let (tx, _block_id) = seq_client.get_transaction(tx_hash).await.unwrap().unwrap();

    match tx {
        LeeTransaction::PrivacyPreserving(privacy_preserving_transaction) => {
            privacy_preserving_transaction
        }
        _ => panic!("Invalid tx type"),
    }
}

pub async fn verify_commitment_is_in_state(
    commitment: Commitment,
    seq_client: &SequencerClient,
) -> bool {
    seq_client
        .get_proofs_and_root(vec![commitment])
        .await
        .ok()
        .and_then(|(proofs, _)| proofs.into_iter().next().flatten())
        .is_some()
}

fn dir_size_bytes(path: &Path) -> u64 {
    let mut total = 0_u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        } else if metadata.is_dir() {
            total = total.saturating_add(dir_size_bytes(&entry.path()));
        } else {
            // Sockets, FIFOs, block/char devices: ignore. Symlinks are
            // already followed by `is_file()` / `is_dir()`.
        }
    }
    total
}

async fn post_chain_config_with_default_parameters(
    channel_id: ChannelId,
    bedrock_addr: SocketAddr,
    sequencer_keys: Vec<[u8; 32]>,
) -> Result<()> {
    log::info!(
        "Sequencer committee is {:?} at {channel_id}",
        sequencer_keys
            .iter()
            .map(|key| Ed25519Key::from_bytes(key).public_key().as_bytes().to_vec())
            .map(hex::encode)
            .collect::<Vec<_>>()
    );

    post_channel_config(
        &BedrockConfig {
            channel_id,
            node_url: config::addr_to_url(config::UrlProtocol::Http, bedrock_addr)?,
            auth: None,
            funding_key: bedrock_funding_key(),
            priority_fee: default_priority_fee(),
        },
        &Ed25519Key::from_bytes(
            sequencer_keys
                .first()
                .expect("Must be at least one sequencer"),
        ),
        sequencer_keys
            .clone()
            .into_iter()
            .map(|key| Ed25519Key::from_bytes(&key).public_key())
            .collect(),
        POSTING_TIMEFRAME_SLOTS,
        POSTING_TIMEOUT_SLOTS,
        1,
        1,
    )
    .await
    .context("Failed to configure the channel committee")
}

async fn wait_until_genesis(client: &SequencerClient) -> Result<()> {
    log::info!("Waiting for leader to send genesis");

    let wait = async {
        loop {
            if client.get_last_block_id().await? >= 1 {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(360), wait)
        .await
        .with_context(|| "Timed out waiting for genesis")?
}

#[expect(clippy::too_many_arguments, reason = "No need to repackage fields")]
async fn build_sequencer_components(
    partial_config: SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    enable_wallet: bool,
    use_prebuilt: bool,
    initial_public_accounts: &[(PrivateKey, u128)],
    initial_private_accounts: &[InitialPrivateAccountForWallet],
    genesis_transactions: Option<Vec<GenesisAction>>,
    sequencer_key: [u8; 32],
    bedrock_channel_id: ChannelId,
    cross_zone_config: Option<CrossZoneConfig>,
    gossip: Option<GossipConfig>,
) -> Result<(SocketAddr, SequencerComponents)> {
    let mut sequencer_setup = SequencerSetup::new(partial_config, bedrock_addr);

    let genesis_actions = if enable_wallet {
        // Wallet genesis must always be present so that
        // setup_public/private_accounts_with_initial_supply can claim from the vault
        // PDAs. When a test supplies custom genesis, merge rather
        // than replace.
        let wallet_genesis =
            config::genesis_from_accounts(initial_public_accounts, initial_private_accounts);
        match genesis_transactions {
            Some(mut custom) => {
                custom.extend(wallet_genesis);
                custom
            }
            None => wallet_genesis,
        }
    } else {
        genesis_transactions.unwrap_or_default()
    };

    if !use_prebuilt {
        sequencer_setup = sequencer_setup.with_genesis(genesis_actions);
    }

    sequencer_setup = sequencer_setup.with_bedrock_signing_key(sequencer_key);
    sequencer_setup = sequencer_setup.with_channel_id(bedrock_channel_id);
    if let Some(cross_zone_config) = cross_zone_config.clone() {
        sequencer_setup = sequencer_setup.with_cross_zone(cross_zone_config);
    }
    if let Some(gossip) = gossip {
        sequencer_setup = sequencer_setup.with_gossip(gossip);
    }

    let (sequencer_handle, temp_sequencer_dir) = sequencer_setup
        .setup()
        .await
        .context("Failed to setup Sequencer")?;

    let sequencer_client = setup::sequencer_client(sequencer_handle.addr())
        .context("Failed to create sequencer client")?;

    Ok((
        sequencer_handle.addr(),
        SequencerComponents {
            sequencer_handle,
            temp_sequencer_dir,
            sequencer_client,
        },
    ))
}
