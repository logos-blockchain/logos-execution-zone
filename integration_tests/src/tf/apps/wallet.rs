use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use lee::{AccountId, PrivateKey};
use tempfile::TempDir;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;
use wallet::{WalletCore, config::WalletConfigOverrides};

use super::LezSequencerClient;
use crate::{config::InitialPrivateAccountForWallet, setup::setup_wallet};

struct WalletComponents {
    wallet: WalletCore,
    _state_dir: TempDir,
    password: String,
}

/// Runtime handle for the deployed LEZ wallet and its state.
#[derive(Clone)]
pub struct LezRuntime {
    wallet: Arc<Mutex<WalletComponents>>,
}

impl LezRuntime {
    fn new(wallet: WalletCore, state_dir: TempDir, password: String) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(WalletComponents {
                wallet,
                _state_dir: state_dir,
                password,
            })),
        }
    }

    /// Runs `f` with shared access to the wallet.
    pub fn with_wallet<R>(&self, f: impl FnOnce(&WalletCore) -> R) -> Result<R, DynError> {
        let components = self.lock_wallet()?;
        Ok(f(&components.wallet))
    }

    /// Runs `f` with exclusive access to the wallet.
    pub fn with_wallet_mut<R>(&self, f: impl FnOnce(&mut WalletCore) -> R) -> Result<R, DynError> {
        let mut components = self.lock_wallet()?;
        Ok(f(&mut components.wallet))
    }

    /// Returns the first public account configured in the wallet.
    pub fn first_public_account(&self) -> Result<AccountId, DynError> {
        self.with_wallet(|wallet| {
            wallet
                .storage()
                .key_chain()
                .public_account_ids()
                .next()
                .map(|(account_id, _)| account_id)
        })?
        .ok_or_else(|| anyhow!("LEZ wallet has no public account").into())
    }

    /// Returns the password used to open the test wallet.
    pub fn wallet_password(&self) -> Result<String, DynError> {
        let components = self.lock_wallet()?;
        Ok(components.password.clone())
    }

    fn lock_wallet(&self) -> Result<MutexGuard<'_, WalletComponents>, DynError> {
        self.wallet
            .lock()
            .map_err(|error| anyhow!("LEZ wallet lock poisoned: {error}").into())
    }
}

/// Deployable LEZ wallet configured from a deployed sequencer client.
#[derive(Clone)]
pub struct WalletApp {
    sequencer_addr: SocketAddr,
    public_accounts: Vec<(PrivateKey, u128)>,
    private_accounts: Vec<InitialPrivateAccountForWallet>,
}

impl WalletApp {
    /// Creates a wallet deployment using a snapshot of sequencer connection and
    /// genesis-account data.
    #[must_use]
    pub fn from_sequencer(sequencer: &LezSequencerClient) -> Self {
        Self {
            sequencer_addr: sequencer.addr(),
            public_accounts: sequencer.public_accounts().to_vec(),
            private_accounts: sequencer.private_accounts().to_vec(),
        }
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for WalletApp {
    type Handle = LezRuntime;

    async fn deploy(self, _ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        let (wallet, state_dir, password) = setup_wallet(
            self.sequencer_addr,
            &self.public_accounts,
            &self.private_accounts,
            WalletConfigOverrides::default(),
        )
        .await
        .context("failed to set up LEZ wallet")?;

        Ok(LezRuntime::new(wallet, state_dir, password))
    }
}
