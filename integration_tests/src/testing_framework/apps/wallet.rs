use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use common::HashType;
use lee::{AccountId, PrivateKey, PublicKey};
use tempfile::TempDir;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;
use tokio::sync::{mpsc, oneshot};
use wallet::{
    AccountIdentity, WalletCore,
    account::{AccountIdWithPrivacy, Label},
    cli::{
        CliAccountMention, Command, SubcommandReturnValue, account::AccountSubcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    config::WalletConfigOverrides,
    program_facades::native_token_transfer::NativeTokenTransfer,
};

use super::LezSequencerClient;
use crate::{config::InitialPrivateAccountForWallet, setup::setup_wallet};

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
    PrivateAccountCommitment {
        account_id: AccountId,
        response: oneshot::Sender<Result<Option<lee_core::Commitment>, String>>,
    },
    PublicAccountSigningKey {
        account_id: AccountId,
        response: oneshot::Sender<Result<Option<PublicKey>, String>>,
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
    PrivateTransfer {
        from: AccountId,
        to: AccountId,
        amount: u128,
        response: oneshot::Sender<Result<HashType, String>>,
    },
    SyncToLatestBlock {
        response: oneshot::Sender<Result<(), String>>,
    },
    NewPublicAccount {
        response: oneshot::Sender<Result<AccountId, String>>,
    },
    PublicTransferToNewAccount {
        from: AccountId,
        to: AccountId,
        amount: u128,
        response: oneshot::Sender<Result<HashType, String>>,
    },
    SetPublicAccountLabel {
        account_id: AccountId,
        label: Label,
        response: oneshot::Sender<Result<(), String>>,
    },
    PublicTransferByLabels {
        from: Label,
        to: Label,
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
                                    .map(|account| account.balance(programs::authenticated_transfer().id()));
                                let _unused = response.send(Ok(balance));
                            }
                            WalletRequest::PrivateAccountCommitment {
                                account_id,
                                response,
                            } => {
                                let commitment = components
                                    .wallet
                                    .get_private_account_commitment(account_id);
                                let _unused = response.send(Ok(commitment));
                            }
                            WalletRequest::PublicAccountSigningKey {
                                account_id,
                                response,
                            } => {
                                let public_key = components
                                    .wallet
                                    .get_account_public_signing_key(account_id)
                                    .map(PublicKey::new_from_private_key);
                                let _unused = response.send(Ok(public_key));
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
                            WalletRequest::PrivateTransfer {
                                from,
                                to,
                                amount,
                                response,
                            } => {
                                let result = wallet::cli::execute_subcommand(
                                    &mut components.wallet,
                                    Command::AuthTransfer(AuthTransferSubcommand::Send {
                                        from: CliAccountMention::Id(
                                            AccountIdWithPrivacy::Private(from),
                                        ),
                                        to: Some(CliAccountMention::Id(
                                            AccountIdWithPrivacy::Private(to),
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
                            WalletRequest::SyncToLatestBlock { response } => {
                                let result = components
                                    .wallet
                                    .sync_to_latest_block()
                                    .await
                                    .map(|_| ())
                                    .map_err(|error| error.to_string());
                                let _unused = response.send(result);
                            }
                            WalletRequest::NewPublicAccount { response } => {
                                let (account_id, _) =
                                    components.wallet.create_new_account_public(None);
                                let result = components
                                    .wallet
                                    .store_persistent_data()
                                    .map(|()| account_id)
                                    .map_err(|error| error.to_string());
                                let _unused = response.send(result);
                            }
                            WalletRequest::PublicTransferToNewAccount {
                                from,
                                to,
                                amount,
                                response,
                            } => {
                                let result = async {
                                    let tx_hash = NativeTokenTransfer(&components.wallet)
                                        .send_public_transfer(
                                            AccountIdentity::Public(from),
                                            AccountIdentity::Public(to),
                                            amount,
                                        )
                                        .await
                                        .map_err(|error| anyhow!(error.to_string()))?;
                                    components
                                        .wallet
                                        .poll_transaction(tx_hash)
                                        .await
                                        .map_err(|error| anyhow!(error.to_string()))?;
                                    components
                                        .wallet
                                        .store_persistent_data()
                                        .map_err(|error| anyhow!(error.to_string()))?;
                                    Ok(tx_hash)
                                }
                                .await
                                .map_err(|error: anyhow::Error| error.to_string());
                                let _unused = response.send(result);
                            }
                            WalletRequest::SetPublicAccountLabel {
                                account_id,
                                label,
                                response,
                            } => {
                                let result = wallet::cli::execute_subcommand(
                                    &mut components.wallet,
                                    Command::Account(AccountSubcommand::Label {
                                        account_id: CliAccountMention::Id(
                                            AccountIdWithPrivacy::Public(account_id),
                                        ),
                                        label,
                                    }),
                                )
                                .await
                                .map(|_| ())
                                .map_err(|error| error.to_string());
                                let _unused = response.send(result);
                            }
                            WalletRequest::PublicTransferByLabels {
                                from,
                                to,
                                amount,
                                response,
                            } => {
                                let result = wallet::cli::execute_subcommand(
                                    &mut components.wallet,
                                    Command::AuthTransfer(AuthTransferSubcommand::Send {
                                        from: CliAccountMention::Label(from),
                                        to: Some(CliAccountMention::Label(to)),
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

    /// Returns the current commitment for an imported private account.
    pub async fn private_account_commitment(
        &self,
        account_id: AccountId,
    ) -> Result<Option<lee_core::Commitment>, DynError> {
        self.request(|response| WalletRequest::PrivateAccountCommitment {
            account_id,
            response,
        })
        .await
    }

    /// Returns the public signing key for an imported public account.
    pub async fn public_account_signing_key(
        &self,
        account_id: AccountId,
    ) -> Result<Option<PublicKey>, DynError> {
        self.request(|response| WalletRequest::PublicAccountSigningKey {
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

    /// Executes an authenticated transfer between two owned private accounts.
    pub async fn private_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<HashType, DynError> {
        self.request(|response| WalletRequest::PrivateTransfer {
            from,
            to,
            amount,
            response,
        })
        .await
    }

    /// Synchronizes the wallet with the latest sequencer block.
    pub async fn sync_to_latest_block(&self) -> Result<(), DynError> {
        self.request(|response| WalletRequest::SyncToLatestBlock { response })
            .await
    }

    /// Creates and persists a fresh public account in the wallet.
    pub async fn new_public_account(&self) -> Result<AccountId, DynError> {
        self.request(|response| WalletRequest::NewPublicAccount { response })
            .await
    }

    /// Executes a public transfer that claims a fresh recipient account.
    pub async fn public_transfer_to_new_account(
        &self,
        from: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<HashType, DynError> {
        self.request(|response| WalletRequest::PublicTransferToNewAccount {
            from,
            to,
            amount,
            response,
        })
        .await
    }

    /// Assigns a label to an imported public account through the wallet actor.
    pub async fn set_public_account_label(
        &self,
        account_id: AccountId,
        label: Label,
    ) -> Result<(), DynError> {
        self.request(|response| WalletRequest::SetPublicAccountLabel {
            account_id,
            label,
            response,
        })
        .await
    }

    /// Executes an authenticated public transfer using wallet-resolved labels.
    pub async fn public_transfer_by_labels(
        &self,
        from: Label,
        to: Label,
        amount: u128,
    ) -> Result<HashType, DynError> {
        self.request(|response| WalletRequest::PublicTransferByLabels {
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
        let (wallet, state_dir, password) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(WalletCore, Option<TempDir>, String)> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to create LEZ wallet setup runtime")?;
                runtime.block_on(async move {
                    let (wallet, initialized_state_dir, password) = match configured_state_dir {
                        Some(setup_home) => crate::setup::setup_wallet_at(
                            std::slice::from_ref(&sequencer_addr),
                            &public_accounts,
                            &private_accounts,
                            WalletConfigOverrides::default(),
                            &setup_home,
                        )
                        .await
                        .context("failed to set up LEZ wallet")
                        .map(|(wallet, _, password)| (wallet, None, password)),
                        None => setup_wallet(
                            std::slice::from_ref(&sequencer_addr),
                            &public_accounts,
                            &private_accounts,
                            WalletConfigOverrides::default(),
                        )
                        .await
                        .context("failed to set up LEZ wallet")
                        .map(|(wallet, wallet_state_dir, password)| {
                            (wallet, Some(wallet_state_dir), password)
                        }),
                    }?;
                    let mut wallet = wallet;
                    // Genesis credits funded accounts directly, so the wallet only syncs.
                    if initialize_private_account_funding {
                        for _private_account in &private_accounts {
                            wallet
                                .sync_to_latest_block()
                                .await
                                .context("failed to synchronize LEZ private wallet accounts")?;
                        }
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
