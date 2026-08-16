use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context as _;
use async_trait::async_trait;
use lee::PrivateKey;
use sequencer_service::SequencerHandle;
use sequencer_service_rpc::{SequencerClient, SequencerClientBuilder};
use tempfile::TempDir;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;

use crate::{
    config::{self, InitialPrivateAccountForWallet, SequencerPartialConfig, UrlProtocol},
    setup::SequencerSetup,
};

struct SequencerInstance {
    client: SequencerClient,
    addr: SocketAddr,
    public_accounts: Vec<(PrivateKey, u128)>,
    private_accounts: Vec<InitialPrivateAccountForWallet>,
    service: Mutex<Option<SequencerHandle>>,
    _state_dir: Option<TempDir>,
}

/// Client and lifetime handle for a deployed LEZ sequencer.
///
/// Clones share the existing sequencer client and keep the sequencer service
/// and its state directory alive until the final clone is dropped.
#[derive(Clone)]
pub struct LezSequencerClient(Arc<SequencerInstance>);

impl LezSequencerClient {
    pub(crate) fn new(
        client: SequencerClient,
        addr: SocketAddr,
        public_accounts: Vec<(PrivateKey, u128)>,
        private_accounts: Vec<InitialPrivateAccountForWallet>,
        service: SequencerHandle,
        state_dir: Option<TempDir>,
    ) -> Self {
        Self(Arc::new(SequencerInstance {
            client,
            addr,
            public_accounts,
            private_accounts,
            service: Mutex::new(Some(service)),
            _state_dir: state_dir,
        }))
    }

    /// Returns the existing LEZ sequencer RPC client.
    #[must_use]
    pub fn client(&self) -> &SequencerClient {
        &self.0.client
    }

    /// Returns the sequencer RPC address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.0.addr
    }

    /// Stops the sequencer service and waits for its owned tasks and store to
    /// be released. Repeated calls are harmless.
    pub async fn shutdown(&self) -> Result<(), DynError> {
        let service = self
            .0
            .service
            .lock()
            .map_err(|error| anyhow::anyhow!("LEZ sequencer shutdown lock poisoned: {error}"))?
            .take();

        if let Some(service) = service {
            service.shutdown().await;
        }

        Ok(())
    }

    pub(super) fn public_accounts(&self) -> &[(PrivateKey, u128)] {
        &self.0.public_accounts
    }

    pub(super) fn private_accounts(&self) -> &[InitialPrivateAccountForWallet] {
        &self.0.private_accounts
    }
}

/// Deployable LEZ sequencer configured with an explicit Bedrock API address.
#[derive(Clone)]
pub struct SequencerApp {
    config: SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    state_dir: Option<PathBuf>,
}

impl SequencerApp {
    /// Creates a sequencer deployment connected to `bedrock_addr`.
    #[must_use]
    pub const fn new(config: SequencerPartialConfig, bedrock_addr: SocketAddr) -> Self {
        Self {
            config,
            bedrock_addr,
            state_dir: None,
        }
    }

    /// Places sequencer state and logs below the supplied scenario artifact
    /// directory.
    #[must_use]
    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "An explicit Send + 'static future is required by the TF deployment boundary"
    )]
    fn deploy_inner(
        self,
    ) -> impl Future<Output = Result<LezSequencerClient, DynError>> + Send + 'static {
        async move {
            let public_accounts = config::default_public_accounts_for_wallet();
            let private_accounts = config::default_private_accounts_for_wallet();
            let genesis = config::genesis_from_accounts(&public_accounts, &private_accounts);
            // If the sequencer moves to a separate process, create a `LocalProcessApp`
            // with its `LaunchSpec` here so TF owns the process lifecycle.
            let setup = SequencerSetup::new(self.config, self.bedrock_addr).with_genesis(genesis);
            let (service, state_dir);
            if let Some(home) = self.state_dir {
                service = setup
                    .setup_in_owned(home)
                    .await
                    .context("failed to set up LEZ sequencer")?;
                state_dir = None;
            } else {
                let (sequencer, temp_dir) = setup
                    .setup()
                    .await
                    .context("failed to set up LEZ sequencer")?;
                service = sequencer;
                state_dir = Some(temp_dir);
            }
            let addr = service.addr();
            let url = config::addr_to_url(UrlProtocol::Http, addr)?;
            let client = SequencerClientBuilder::default().build(url)?;

            Ok(LezSequencerClient::new(
                client,
                addr,
                public_accounts,
                private_accounts,
                service,
                state_dir,
            ))
        }
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for SequencerApp {
    type Handle = LezSequencerClient;

    async fn deploy(self, _ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        self.deploy_inner().await
    }
}
