use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use common::HashType;
use lee::{AccountId, PrivateKey};
use tempfile::TempDir;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;
use tokio::sync::{mpsc, oneshot};
use wallet::{
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    config::WalletConfigOverrides,
};

use super::LezSequencerClient;
use crate::{
    config::InitialPrivateAccountForWallet,
    setup::{
        setup_private_accounts_with_initial_supply, setup_public_accounts_with_initial_supply,
        setup_wallet,
    },
};

struct WalletComponents {
    wallet: WalletCore,
    _state_dir: Option<TempDir>,
    password: String,
}

enum WalletRequest {
    ExistingPublicAccounts {
        response: oneshot::Sender<Result<Vec<AccountId>, String>>,
    },
    ExistingPrivateAccounts {
        response: oneshot::Sender<Result<Vec<AccountId>, String>>,
    },
    PrivateAccountBalance {
        account_id: AccountId,
        response: oneshot::Sender<Result<Option<u128>, String>>,
    },
    FirstPublicAccount {
        response: oneshot::Sender<Result<Option<AccountId>, String>>,
    },
    PublicTransfer {
        from: AccountId,
        to: AccountId,
        amount: u128,
        response: oneshot::Sender<Result<HashType, String>>,
    },
    WalletPassword {
        response: oneshot::Sender<Result<String, String>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), String>>,
    },
}

struct WalletActor {
    requests: mpsc::Sender<WalletRequest>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl WalletActor {
    fn new(components: WalletComponents) -> Result<Self, DynError> {
        let (requests, mut receiver) = mpsc::channel(16);
        let join_handle = std::thread::Builder::new()
            .name("lez-wallet".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("LEZ wallet actor runtime should be constructible");

                runtime.block_on(async move {
                    let mut components = components;
                    while let Some(request) = receiver.recv().await {
                        match request {
                            WalletRequest::ExistingPublicAccounts { response } => {
                                let accounts = components
                                    .wallet
                                    .storage()
                                    .key_chain()
                                    .public_account_ids()
                                    .map(|(account_id, _)| account_id)
                                    .collect();
                                let _unused = response.send(Ok(accounts));
                            }
                            WalletRequest::ExistingPrivateAccounts { response } => {
                                let accounts = components
                                    .wallet
                                    .storage()
                                    .key_chain()
                                    .private_account_ids()
                                    .map(|(account_id, _)| account_id)
                                    .collect();
                                let _unused = response.send(Ok(accounts));
                            }
                            WalletRequest::PrivateAccountBalance {
                                account_id,
                                response,
                            } => {
                                let balance = components
                                    .wallet
                                    .get_account_private(account_id)
                                    .map(|account| account.balance);
                                let _unused = response.send(Ok(balance));
                            }
                            WalletRequest::FirstPublicAccount { response } => {
                                let account = components
                                    .wallet
                                    .storage()
                                    .key_chain()
                                    .public_account_ids()
                                    .next()
                                    .map(|(account_id, _)| account_id);
                                let _unused = response.send(Ok(account));
                            }
                            WalletRequest::PublicTransfer {
                                from,
                                to,
                                amount,
                                response,
                            } => {
                                let result = wallet::cli::execute_subcommand(
                                    &mut components.wallet,
                                    Command::AuthTransfer(AuthTransferSubcommand::Send {
                                        from: CliAccountMention::Id(AccountIdWithPrivacy::Public(
                                            from,
                                        )),
                                        to: Some(CliAccountMention::Id(
                                            AccountIdWithPrivacy::Public(to),
                                        )),
                                        to_npk: None,
                                        to_vpk: None,
                                        to_keys: None,
                                        to_identifier: Some(0),
                                        amount,
                                    }),
                                )
                                .await
                                .and_then(|result| {
                                    #[expect(
                                        clippy::wildcard_enum_match_arm,
                                        reason = "Only TransactionExecuted is valid for a transfer request"
                                    )]
                                    match result {
                                        SubcommandReturnValue::TransactionExecuted { tx_hash } => {
                                            Ok(tx_hash)
                                        }
                                        other => {
                                            anyhow::bail!(
                                                "expected TransactionExecuted, got {other:?}"
                                            )
                                        }
                                    }
                                })
                                .map_err(|error| error.to_string());
                                let _unused = response.send(result);
                            }
                            WalletRequest::WalletPassword { response } => {
                                let _unused = response.send(Ok(components.password.clone()));
                            }
                            WalletRequest::Shutdown { response } => {
                                let _unused = response.send(Ok(()));
                                break;
                            }
                        }
                    }
                });
            })
            .context("failed to start LEZ wallet actor")?;

        Ok(Self {
            requests,
            join_handle: Mutex::new(Some(join_handle)),
        })
    }
}

/// Runtime handle for the deployed LEZ wallet and its state.
#[derive(Clone)]
pub struct LezRuntime {
    actor: Arc<WalletActor>,
}

impl LezRuntime {
    fn new(
        wallet: WalletCore,
        state_dir: Option<TempDir>,
        password: String,
    ) -> Result<Self, DynError> {
        Ok(Self {
            actor: Arc::new(WalletActor::new(WalletComponents {
                wallet,
                _state_dir: state_dir,
                password,
            })?),
        })
    }

    async fn request<T>(
        &self,
        request: impl FnOnce(oneshot::Sender<Result<T, String>>) -> WalletRequest,
    ) -> Result<T, DynError> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .requests
            .send(request(response))
            .await
            .map_err(|error| anyhow!("LEZ wallet actor is no longer running: {error}"))?;
        receiver
            .await
            .map_err(|error| anyhow!("LEZ wallet actor dropped its response: {error}"))?
            .map_err(|error| anyhow!(error).into())
    }

    /// Returns the first public account configured in the wallet.
    pub async fn first_public_account(&self) -> Result<AccountId, DynError> {
        self.request(|response| WalletRequest::FirstPublicAccount { response })
            .await?
            .ok_or_else(|| anyhow!("LEZ wallet has no public account").into())
    }

    /// Returns all public account IDs configured in the wallet.
    pub async fn existing_public_accounts(&self) -> Result<Vec<AccountId>, DynError> {
        self.request(|response| WalletRequest::ExistingPublicAccounts { response })
            .await
    }

    /// Returns all private account IDs configured in the wallet.
    pub async fn existing_private_accounts(&self) -> Result<Vec<AccountId>, DynError> {
        self.request(|response| WalletRequest::ExistingPrivateAccounts { response })
            .await
    }

    /// Returns the locally synchronized balance of an imported private account.
    pub async fn private_account_balance(
        &self,
        account_id: AccountId,
    ) -> Result<Option<u128>, DynError> {
        self.request(|response| WalletRequest::PrivateAccountBalance {
            account_id,
            response,
        })
        .await
    }

    /// Returns the password used to open the test wallet.
    pub async fn wallet_password(&self) -> Result<String, DynError> {
        self.request(|response| WalletRequest::WalletPassword { response })
            .await
    }

    /// Executes an authenticated transfer between two owned public accounts.
    pub async fn public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<HashType, DynError> {
        self.request(|response| WalletRequest::PublicTransfer {
            from,
            to,
            amount,
            response,
        })
        .await
    }

    /// Stop the wallet actor and wait for its owning thread to finish.
    pub async fn shutdown(&self) -> Result<(), DynError> {
        let join_handle = self
            .actor
            .join_handle
            .lock()
            .map_err(|error| anyhow!("LEZ wallet actor join lock poisoned: {error}"))?
            .take();

        let Some(join_handle) = join_handle else {
            return Ok(());
        };

        let request_result = self
            .request(|response| WalletRequest::Shutdown { response })
            .await;
        let join_result = tokio::task::spawn_blocking(move || join_handle.join())
            .await
            .map_err(|error| anyhow!("failed to join LEZ wallet actor: {error}"))?;
        if join_result.is_err() {
            return Err(anyhow!("LEZ wallet actor panicked").into());
        }

        request_result
    }
}

/// Deployable LEZ wallet configured from a deployed sequencer client.
#[derive(Clone)]
pub struct WalletApp {
    sequencer_addr: SocketAddr,
    public_accounts: Vec<(PrivateKey, u128)>,
    private_accounts: Vec<InitialPrivateAccountForWallet>,
    state_dir: Option<PathBuf>,
    initialize_private_accounts: bool,
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
            state_dir: None,
            initialize_private_accounts: true,
        }
    }

    /// Places wallet state and logs below the supplied scenario artifact
    /// directory.
    #[must_use]
    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Skip privacy-preserving account funding when the caller only needs the
    /// public-account fixture. The normal TF wallet fixture keeps this enabled
    /// so it matches [`test_fixtures::TestContext`] initialization semantics.
    #[must_use]
    pub const fn without_private_account_initialization(mut self) -> Self {
        self.initialize_private_accounts = false;
        self
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for WalletApp {
    type Handle = LezRuntime;

    async fn deploy(self, _ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        let Self {
            sequencer_addr,
            public_accounts,
            private_accounts,
            state_dir: configured_state_dir,
            initialize_private_accounts: initialize_private_account_funding,
        } = self;
        // WalletCore initialization currently exposes a non-general borrowed
        // lifetime in its async API. Keep that implementation detail inside a
        // dedicated blocking thread/runtime; scenario operations use the
        // actor below and never create nested runtimes.
        let setup_public_accounts = public_accounts.clone();
        let setup_private_accounts = private_accounts.clone();
        let setup_state_dir = configured_state_dir.clone();
        let initialize_public_accounts = public_accounts.clone();
        let private_accounts_to_initialize = private_accounts.clone();
        let (wallet, state_dir, password) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(WalletCore, Option<TempDir>, String)> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to create LEZ wallet setup runtime")?;
                runtime.block_on(async move {
                    let (wallet, initialized_state_dir, password) = match setup_state_dir {
                        Some(setup_home) => crate::setup::setup_wallet_at(
                            sequencer_addr,
                            &setup_public_accounts,
                            &setup_private_accounts,
                            WalletConfigOverrides::default(),
                            &setup_home,
                        )
                        .await
                        .context("failed to set up LEZ wallet")
                        .map(|(wallet, _, password)| (wallet, None, password)),
                        None => setup_wallet(
                            sequencer_addr,
                            &setup_public_accounts,
                            &setup_private_accounts,
                            WalletConfigOverrides::default(),
                        )
                        .await
                        .context("failed to set up LEZ wallet")
                        .map(|(wallet, wallet_state_dir, password)| {
                            (wallet, Some(wallet_state_dir), password)
                        }),
                    }?;
                    let mut wallet = wallet;
                    setup_public_accounts_with_initial_supply(
                        &mut wallet,
                        &initialize_public_accounts,
                    )
                    .await
                    .context("failed to initialize LEZ public wallet accounts")?;
                    if initialize_private_account_funding {
                        setup_private_accounts_with_initial_supply(
                            &mut wallet,
                            &private_accounts_to_initialize,
                        )
                        .await
                        .context("failed to initialize LEZ private wallet accounts")?;
                    }
                    Ok((wallet, initialized_state_dir, password))
                })
            },
        )
        .await
        .context("LEZ wallet setup task failed")??;

        LezRuntime::new(wallet, state_dir, password)
    }
}
