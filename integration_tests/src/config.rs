use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use bytesize::ByteSize;
use common::block::{AccountInitialData, CommitmentsInitialData};
use indexer_service::{BackoffConfig, ChannelId, ClientConfig, IndexerConfig};
use key_protocol::key_management::KeyChain;
use nssa::{Account, AccountId, PrivateKey, PublicKey};
use nssa_core::{account::Data, program::DEFAULT_PROGRAM_ID};
use sequencer_core::config::{BedrockConfig, SequencerConfig};
use url::Url;
use wallet::config::{
    InitialAccountData, InitialAccountDataPrivate, InitialAccountDataPublic, WalletConfig,
};

/// Sequencer config options available for custom changes in integration tests.
#[derive(Debug, Clone, Copy)]
pub struct SequencerPartialConfig {
    pub max_num_tx_in_block: usize,
    pub max_block_size: ByteSize,
    pub mempool_max_size: usize,
    pub block_create_timeout: Duration,
}

impl Default for SequencerPartialConfig {
    fn default() -> Self {
        Self {
            max_num_tx_in_block: 20,
            max_block_size: ByteSize::mib(1),
            mempool_max_size: 10_000,
            block_create_timeout: Duration::from_secs(10),
        }
    }
}

pub struct InitialData {
    pub public_accounts: Vec<(PrivateKey, u128)>,
    pub private_accounts: Vec<(KeyChain, Account)>,
}

impl InitialData {
    #[must_use]
    pub fn with_two_public_and_two_private_initialized_accounts() -> Self {
        let mut public_alice_private_key = PrivateKey::new_os_random();
        let mut public_alice_public_key =
            PublicKey::new_from_private_key(&public_alice_private_key);
        let mut public_alice_account_id = AccountId::from(&public_alice_public_key);

        let mut public_bob_private_key = PrivateKey::new_os_random();
        let mut public_bob_public_key = PublicKey::new_from_private_key(&public_bob_private_key);
        let mut public_bob_account_id = AccountId::from(&public_bob_public_key);

        // Ensure consistent ordering
        if public_alice_account_id > public_bob_account_id {
            std::mem::swap(&mut public_alice_private_key, &mut public_bob_private_key);
            std::mem::swap(&mut public_alice_public_key, &mut public_bob_public_key);
            std::mem::swap(&mut public_alice_account_id, &mut public_bob_account_id);
        }

        let mut private_charlie_key_chain = KeyChain::new_os_random();
        let mut private_charlie_account_id =
            AccountId::from(&private_charlie_key_chain.nullifer_public_key);

        let mut private_david_key_chain = KeyChain::new_os_random();
        let mut private_david_account_id =
            AccountId::from(&private_david_key_chain.nullifer_public_key);

        // Ensure consistent ordering
        if private_charlie_account_id > private_david_account_id {
            std::mem::swap(&mut private_charlie_key_chain, &mut private_david_key_chain);
            std::mem::swap(
                &mut private_charlie_account_id,
                &mut private_david_account_id,
            );
        }

        Self {
            public_accounts: vec![
                (public_alice_private_key, 10_000),
                (public_bob_private_key, 20_000),
            ],
            private_accounts: vec![
                (
                    private_charlie_key_chain,
                    Account {
                        balance: 10_000,
                        data: Data::default(),
                        program_owner: DEFAULT_PROGRAM_ID,
                        nonce: 0,
                    },
                ),
                (
                    private_david_key_chain,
                    Account {
                        balance: 20_000,
                        data: Data::default(),
                        program_owner: DEFAULT_PROGRAM_ID,
                        nonce: 0,
                    },
                ),
            ],
        }
    }

    fn sequencer_initial_accounts(&self) -> Vec<AccountInitialData> {
        self.public_accounts
            .iter()
            .map(|(priv_key, balance)| {
                let pub_key = PublicKey::new_from_private_key(priv_key);
                let account_id = AccountId::from(&pub_key);
                AccountInitialData {
                    account_id,
                    balance: *balance,
                }
            })
            .collect()
    }

    fn sequencer_initial_commitments(&self) -> Vec<CommitmentsInitialData> {
        self.private_accounts
            .iter()
            .map(|(key_chain, account)| CommitmentsInitialData {
                npk: key_chain.nullifer_public_key.clone(),
                account: account.clone(),
            })
            .collect()
    }

    fn wallet_initial_accounts(&self) -> Vec<InitialAccountData> {
        self.public_accounts
            .iter()
            .map(|(priv_key, _)| {
                let pub_key = PublicKey::new_from_private_key(priv_key);
                let account_id = AccountId::from(&pub_key);
                InitialAccountData::Public(InitialAccountDataPublic {
                    account_id,
                    pub_sign_key: priv_key.clone(),
                })
            })
            .chain(self.private_accounts.iter().map(|(key_chain, account)| {
                let account_id = AccountId::from(&key_chain.nullifer_public_key);
                InitialAccountData::Private(Box::new(InitialAccountDataPrivate {
                    account_id,
                    account: account.clone(),
                    key_chain: key_chain.clone(),
                }))
            }))
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UrlProtocol {
    Http,
    Ws,
}

impl std::fmt::Display for UrlProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Ws => write!(f, "ws"),
        }
    }
}

pub fn indexer_config(
    bedrock_addr: SocketAddr,
    home: PathBuf,
    initial_data: &InitialData,
) -> Result<IndexerConfig> {
    Ok(IndexerConfig {
        home,
        consensus_info_polling_interval: Duration::from_secs(1),
        bedrock_client_config: ClientConfig {
            addr: addr_to_url(UrlProtocol::Http, bedrock_addr)
                .context("Failed to convert bedrock addr to URL")?,
            auth: None,
            backoff: BackoffConfig {
                start_delay: Duration::from_millis(100),
                max_retries: 10,
            },
        },
        initial_accounts: initial_data.sequencer_initial_accounts(),
        initial_commitments: initial_data.sequencer_initial_commitments(),
        signing_key: [37; 32],
        channel_id: bedrock_channel_id(),
    })
}

pub fn sequencer_config(
    partial: SequencerPartialConfig,
    home: PathBuf,
    bedrock_addr: SocketAddr,
    indexer_addr: SocketAddr,
    initial_data: &InitialData,
) -> Result<SequencerConfig> {
    let SequencerPartialConfig {
        max_num_tx_in_block,
        max_block_size,
        mempool_max_size,
        block_create_timeout,
    } = partial;

    Ok(SequencerConfig {
        home,
        override_rust_log: None,
        genesis_id: 1,
        is_genesis_random: true,
        max_num_tx_in_block,
        max_block_size,
        mempool_max_size,
        block_create_timeout,
        retry_pending_blocks_timeout: Duration::from_secs(120),
        port: 0,
        initial_accounts: initial_data.sequencer_initial_accounts(),
        initial_commitments: initial_data.sequencer_initial_commitments(),
        signing_key: [37; 32],
        bedrock_config: BedrockConfig {
            backoff: BackoffConfig {
                start_delay: Duration::from_millis(100),
                max_retries: 5,
            },
            channel_id: bedrock_channel_id(),
            node_url: addr_to_url(UrlProtocol::Http, bedrock_addr)
                .context("Failed to convert bedrock addr to URL")?,
            auth: None,
        },
        indexer_rpc_url: addr_to_url(UrlProtocol::Ws, indexer_addr)
            .context("Failed to convert indexer addr to URL")?,
    })
}

pub fn wallet_config(
    sequencer_addr: SocketAddr,
    initial_data: &InitialData,
) -> Result<WalletConfig> {
    Ok(WalletConfig {
        override_rust_log: None,
        sequencer_addr: addr_to_url(UrlProtocol::Http, sequencer_addr)
            .context("Failed to convert sequencer addr to URL")?,
        seq_poll_timeout: Duration::from_secs(30),
        seq_tx_poll_max_blocks: 15,
        seq_poll_max_retries: 10,
        seq_block_poll_max_amount: 100,
        initial_accounts: initial_data.wallet_initial_accounts(),
        basic_auth: None,
    })
}

pub fn addr_to_url(protocol: UrlProtocol, addr: SocketAddr) -> Result<Url> {
    // Convert 0.0.0.0 to 127.0.0.1 for client connections
    // When binding to port 0, the server binds to 0.0.0.0:<random_port>
    // but clients need to connect to 127.0.0.1:<port> to work reliably
    let url_string = if addr.ip().is_unspecified() {
        format!("{protocol}://127.0.0.1:{}", addr.port())
    } else {
        format!("{protocol}://{addr}")
    };

    url_string.parse().map_err(Into::into)
}

fn bedrock_channel_id() -> ChannelId {
    let channel_id: [u8; 32] = [0_u8, 1]
        .repeat(16)
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    ChannelId::from(channel_id)
}
