use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, sync::Arc};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use logos_blockchain_key_management_system_service::keys::ZkKey;
use logos_blockchain_testing_framework::{
    DeploymentBuilder, LbcEnv, TopologyConfig,
    configs::wallet::{WalletAccount, WalletConfig},
};
use num_bigint::BigUint;
use tempfile::TempDir;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext, LocalAppCluster};
use testing_framework_core::scenario::DynError;

/// A TF-managed Logos blockchain cluster used as LEZ's Bedrock layer.
///
/// Logos owns node configuration generation through [`TopologyConfig`] and
/// [`DeploymentBuilder`]. Callers can use the default node-count constructor or
/// provide a configured builder without duplicating Logos deployment logic.
#[derive(Clone)]
pub struct BedrockApp {
    builder: DeploymentBuilder,
    scenario_base_dir: Option<PathBuf>,
}

impl Default for BedrockApp {
    fn default() -> Self {
        Self::nodes(Self::DEFAULT_NODES)
    }
}

impl BedrockApp {
    /// Default number of validators in a local Bedrock cluster.
    pub const DEFAULT_NODES: usize = 2;

    /// Creates a Bedrock deployment with the requested validator count.
    #[must_use]
    pub fn nodes(nodes: usize) -> Self {
        let builder = DeploymentBuilder::new(TopologyConfig::with_node_numbers(nodes))
            .with_security_param(NonZeroU32::new(5).expect("five is non-zero"))
            .with_slot_activation_coeff(1, NonZeroU32::new(2).expect("two is non-zero"))
            .with_wallet_config(lez_funding_wallet());
        Self::from_builder(builder)
    }

    /// Creates a Bedrock deployment from a Logos deployment builder.
    ///
    /// The application's temporary state directory is applied when the
    /// deployment starts; all other builder settings are preserved.
    #[must_use]
    pub const fn from_builder(builder: DeploymentBuilder) -> Self {
        Self {
            builder,
            scenario_base_dir: None,
        }
    }

    /// Replaces the validator count while preserving other builder settings.
    #[must_use]
    pub fn with_nodes(mut self, nodes: usize) -> Self {
        self.builder = self.builder.with_node_count(nodes);
        self
    }

    /// Places Bedrock node runtime directories below the supplied scenario
    /// artifact directory.
    #[must_use]
    pub fn with_scenario_base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.scenario_base_dir = Some(dir.into());
        self
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for BedrockApp {
    type Handle = BedrockCluster;

    async fn deploy(self, ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        let (scenario_base_dir, state_dir);
        if let Some(dir) = self.scenario_base_dir {
            std::fs::create_dir_all(&dir).context("failed to create Bedrock scenario directory")?;
            scenario_base_dir = dir;
            state_dir = None;
        } else {
            let temp_dir =
                tempfile::tempdir().context("failed to create Bedrock state directory")?;
            scenario_base_dir = temp_dir.path().to_owned();
            state_dir = Some(Arc::new(temp_dir));
        }
        let deployment = self
            .builder
            .scenario_base_dir(scenario_base_dir)
            .build()
            .context("failed to build Bedrock cluster deployment")?;
        let cluster = Box::pin(ctx.deploy_local_cluster::<LbcEnv>(deployment)).await?;
        let primary_api_addr = first_api_addr(&cluster)?;

        Ok(BedrockCluster {
            cluster,
            primary_api_addr,
            _state_dir: state_dir,
        })
    }
}

/// Client access and lifetime ownership for the deployed Bedrock cluster.
#[derive(Clone)]
pub struct BedrockCluster {
    cluster: LocalAppCluster<LbcEnv>,
    primary_api_addr: SocketAddr,
    _state_dir: Option<Arc<TempDir>>,
}

impl BedrockCluster {
    /// Returns the underlying TF cluster handle for node-level control.
    #[must_use]
    pub const fn cluster(&self) -> &LocalAppCluster<LbcEnv> {
        &self.cluster
    }

    /// Returns the node API selected as the primary endpoint for LEZ services.
    ///
    /// The current local stack intentionally connects both the indexer and the
    /// sequencer to the first Bedrock node. This is not a failover endpoint.
    #[must_use]
    pub const fn primary_api_addr(&self) -> SocketAddr {
        self.primary_api_addr
    }

    /// Returns the number of Logos nodes in the Bedrock cluster.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.cluster.node_count()
    }

    /// Queries every node's consensus state.
    pub async fn cryptarchia_info(&self) -> Result<(), DynError> {
        for client in self.cluster.clients() {
            client.consensus_info().await?;
        }
        Ok(())
    }
}

fn first_api_addr(cluster: &LocalAppCluster<LbcEnv>) -> Result<SocketAddr, DynError> {
    let client = cluster
        .first_client()
        .ok_or_else(|| anyhow!("Bedrock cluster has no node clients"))?;
    client
        .base_url()
        .socket_addrs(|| None)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Bedrock node URL has no socket address").into())
}

fn lez_funding_wallet() -> WalletConfig {
    const FUNDING_SECRET_KEY: [u8; 32] = [
        0x6c, 0x64, 0x5c, 0xd4, 0x63, 0x6d, 0x9c, 0x4c, 0x36, 0xa3, 0x7a, 0x9a, 0xea, 0xbc, 0xaa,
        0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    WalletConfig::new(vec![WalletAccount {
        label: "lez-sequencer-funding".to_owned(),
        secret_key: ZkKey::from(BigUint::from_bytes_le(&FUNDING_SECRET_KEY)),
        value: 1_000_000,
    }])
}
