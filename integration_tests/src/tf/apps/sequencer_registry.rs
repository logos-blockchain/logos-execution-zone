use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use logos_blockchain_key_management_system_service::keys::ED25519_SECRET_KEY_SIZE;
use sequencer_core::config::GenesisAction;
use sequencer_service_rpc::SequencerClientBuilder;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;

use super::LezSequencerClient;
use crate::{
    config::{self, SequencerPartialConfig, UrlProtocol},
    setup::SequencerSetup,
};

#[derive(Clone, Copy)]
struct RegisteredSequencer {
    config: SequencerPartialConfig,
    signing_key: [u8; ED25519_SECRET_KEY_SIZE],
}

struct SequencerRegistryInstance {
    config: SequencerPartialConfig,
    registered: Mutex<HashMap<String, RegisteredSequencer>>,
    started: Mutex<HashMap<String, LezSequencerClient>>,
    initial_committee_aliases: Mutex<Option<Vec<String>>>,
    genesis: Mutex<Option<Vec<GenesisAction>>>,
    bedrock_addr: SocketAddr,
    scenario_base_dir: Option<PathBuf>,
}

/// TF-owned sequencer lifecycles for a Cucumber sequencer-registry scenario.
#[derive(Clone)]
pub struct LezSequencerRegistryClient(Arc<SequencerRegistryInstance>);

impl LezSequencerRegistryClient {
    fn new(
        config: SequencerPartialConfig,
        bedrock_addr: SocketAddr,
        scenario_base_dir: Option<PathBuf>,
    ) -> Self {
        Self(Arc::new(SequencerRegistryInstance {
            config,
            registered: Mutex::new(HashMap::new()),
            started: Mutex::new(HashMap::new()),
            initial_committee_aliases: Mutex::new(None),
            genesis: Mutex::new(None),
            bedrock_addr,
            scenario_base_dir,
        }))
    }

    /// Registers a sequencer alias and its signing identity.
    pub fn register(
        &self,
        alias: impl Into<String>,
        signing_key: [u8; ED25519_SECRET_KEY_SIZE],
    ) -> Result<(), DynError> {
        let alias = alias.into();
        if self
            .0
            .genesis
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?
            .is_some()
        {
            return Err(anyhow!(
                "cannot register sequencer alias '{alias}' after sequencer startup"
            )
            .into());
        }
        let mut registered = self
            .0
            .registered
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
        if registered.contains_key(&alias) {
            return Err(anyhow!("sequencer alias '{alias}' is already registered").into());
        }
        registered.insert(
            alias,
            RegisteredSequencer {
                config: self.config(),
                signing_key,
            },
        );
        Ok(())
    }

    fn config(&self) -> SequencerPartialConfig {
        self.0.config
    }

    /// Selects the registered aliases that will be staked in shared genesis.
    pub fn configure_initial_committee(&self, aliases: &[String]) -> Result<(), DynError> {
        if aliases.is_empty() {
            return Err(anyhow!("the initial committee must contain at least one alias").into());
        }

        let genesis = self
            .0
            .genesis
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
        if genesis.is_some() {
            return Err(
                anyhow!("cannot configure the initial committee after sequencer startup").into(),
            );
        }

        let registered = self
            .0
            .registered
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
        for alias in aliases {
            if !registered.contains_key(alias) {
                return Err(anyhow!("initial committee alias '{alias}' is not registered").into());
            }
        }
        drop(registered);

        let mut configured = self
            .0
            .initial_committee_aliases
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
        if configured.is_some() {
            return Err(anyhow!("the initial committee is already configured").into());
        }
        *configured = Some(aliases.to_vec());
        Ok(())
    }

    fn genesis(&self) -> Result<Vec<GenesisAction>, DynError> {
        let mut genesis = self
            .0
            .genesis
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
        if let Some(genesis) = genesis.as_ref() {
            return Ok(genesis.clone());
        }

        let aliases = self
            .0
            .initial_committee_aliases
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?
            .clone()
            .ok_or_else(|| anyhow!("the initial committee has not been configured"))?;
        let registered = self
            .0
            .registered
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
        let signing_keys = aliases
            .iter()
            .map(|alias| {
                registered
                    .get(alias)
                    .map(|registration| registration.signing_key)
                    .ok_or_else(|| anyhow!("initial committee alias '{alias}' is not registered"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let generated = test_fixtures::config::genesis_sequencer_stakes(&signing_keys)
            .context("failed to build founding sequencer stakes")?;
        *genesis = Some(generated.clone());
        Ok(generated)
    }

    /// Starts the registered sequencer identified by `alias`.
    pub async fn start(&self, alias: &str) -> Result<(), DynError> {
        let registration = self
            .0
            .registered
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?
            .get(alias)
            .copied()
            .ok_or_else(|| anyhow!("sequencer alias '{alias}' is not registered"))?;
        if self
            .0
            .started
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?
            .contains_key(alias)
        {
            return Ok(());
        }

        let state_dir = self
            .0
            .scenario_base_dir
            .as_ref()
            .map(|dir| dir.join("lez").join(format!("sequencer-{alias}")));
        let genesis = self.genesis()?;
        let sequencer = deploy_registered_sequencer(
            registration.config,
            self.0.bedrock_addr,
            registration.signing_key,
            genesis,
            state_dir,
        )
        .await?;

        let mut sequencer = Some(sequencer);
        let duplicate = {
            let mut started = self
                .0
                .started
                .lock()
                .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?;
            if started.contains_key(alias) {
                true
            } else {
                started.insert(
                    alias.to_owned(),
                    sequencer.take().expect("sequencer is present"),
                );
                false
            }
        };
        if duplicate {
            return sequencer
                .expect("duplicate sequencer remains available")
                .shutdown()
                .await;
        }
        Ok(())
    }

    /// Returns a started sequencer identified by `alias`.
    #[must_use]
    pub fn sequencer(&self, alias: &str) -> Option<LezSequencerClient> {
        let sequencers = self.0.started.lock().ok()?;
        Some(sequencers.get(alias)?.clone())
    }

    /// Returns the registered signing key for a sequencer alias.
    #[must_use]
    pub fn signing_key(&self, alias: &str) -> Option<[u8; ED25519_SECRET_KEY_SIZE]> {
        let sequencers = self.0.registered.lock().ok()?;
        Some(sequencers.get(alias)?.signing_key)
    }

    /// Stops every started sequencer and preserves all component failures.
    pub async fn shutdown(&self) -> Result<(), DynError> {
        let started = self
            .0
            .started
            .lock()
            .map_err(|error| anyhow!("sequencer registry lock poisoned: {error}"))?
            .drain()
            .collect::<Vec<_>>();
        let mut failures = Vec::new();
        for (alias, sequencer) in started {
            if let Err(error) = sequencer.shutdown().await {
                failures.push(format!("sequencer '{alias}': {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "sequencer registry shutdown failed:\n- {}",
                failures.join("\n- ")
            )
            .into())
        }
    }
}

/// Deploys an empty alias-based sequencer registry.
#[derive(Clone)]
pub struct LezSequencerRegistryApp {
    config: SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    scenario_base_dir: Option<PathBuf>,
}

impl LezSequencerRegistryApp {
    /// Creates an empty sequencer registry connected to the Bedrock endpoint.
    #[must_use]
    pub const fn new(config: SequencerPartialConfig, bedrock_addr: SocketAddr) -> Self {
        Self {
            config,
            bedrock_addr,
            scenario_base_dir: None,
        }
    }

    /// Places registered sequencer state below the scenario artifact directory.
    #[must_use]
    pub fn with_scenario_base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.scenario_base_dir = Some(dir.into());
        self
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for LezSequencerRegistryApp {
    type Handle = LezSequencerRegistryClient;

    async fn deploy(self, _ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        Ok(LezSequencerRegistryClient::new(
            self.config,
            self.bedrock_addr,
            self.scenario_base_dir,
        ))
    }
}

async fn deploy_registered_sequencer(
    config: SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    signing_key: [u8; ED25519_SECRET_KEY_SIZE],
    genesis: Vec<GenesisAction>,
    state_dir: Option<PathBuf>,
) -> Result<LezSequencerClient, DynError> {
    let setup = SequencerSetup::new(config, bedrock_addr)
        .with_genesis(genesis)
        .with_bedrock_signing_key(signing_key);
    let (service, owned_state_dir) = if let Some(state_dir) = state_dir {
        (
            setup
                .setup_in_owned(state_dir)
                .await
                .context("failed to set up registered sequencer")?,
            None,
        )
    } else {
        let (service, temporary_state_dir) = setup
            .setup()
            .await
            .context("failed to set up registered sequencer")?;
        (service, Some(temporary_state_dir))
    };
    let addr = service.addr();
    let url = config::addr_to_url(UrlProtocol::Http, addr)?;
    let client = SequencerClientBuilder::default().build(url)?;
    Ok(LezSequencerClient::new(
        client,
        addr,
        Vec::new(),
        Vec::new(),
        service,
        owned_state_dir,
    ))
}
