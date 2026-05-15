use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use bytesize::ByteSize;
use indexer_service::{ChannelId, ClientConfig, IndexerConfig};
use key_protocol::key_management::KeyChain;
use nssa::{AccountId, PrivateKey, PublicKey};
use nssa_core::Identifier;
use sequencer_core::config::{BedrockConfig, GenesisAction, SequencerConfig};
use url::Url;
use wallet::config::WalletConfig;

pub const INITIAL_PUBLIC_BALANCES_FOR_WALLET: [u128; 2] = [10_000, 20_000];
pub const INITIAL_PRIVATE_BALANCES_FOR_WALLET: [u128; 2] = [10_000, 20_000];

#[derive(Clone)]
pub struct InitialPrivateAccountForWallet {
    pub key_chain: KeyChain,
    pub identifier: Identifier,
    pub balance: u128,
}

impl InitialPrivateAccountForWallet {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::from((&self.key_chain.nullifier_public_key, self.identifier))
    }
}

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

pub fn sequencer_config(
    partial: SequencerPartialConfig,
    home: PathBuf,
    bedrock_addr: SocketAddr,
    genesis_transactions: Vec<GenesisAction>,
) -> Result<SequencerConfig> {
    let SequencerPartialConfig {
        max_num_tx_in_block,
        max_block_size,
        mempool_max_size,
        block_create_timeout,
    } = partial;

    Ok(SequencerConfig {
        home,
        max_num_tx_in_block,
        max_block_size,
        mempool_max_size,
        block_create_timeout,
        retry_pending_blocks_timeout: Duration::from_secs(5),
        genesis: genesis_transactions,
        signing_key: [37; 32],
        bedrock_config: BedrockConfig {
            channel_id: bedrock_channel_id(),
            node_url: addr_to_url(UrlProtocol::Http, bedrock_addr)
                .context("Failed to convert bedrock addr to URL")?,
            auth: None,
        },
    })
}

#[must_use]
pub fn default_public_accounts_for_wallet() -> Vec<(PrivateKey, u128)> {
    let mut private_keys = vec![PrivateKey::new_os_random(), PrivateKey::new_os_random()];
    private_keys.sort_unstable_by_key(|private_key| {
        AccountId::from(&PublicKey::new_from_private_key(private_key))
    });

    private_keys
        .into_iter()
        .zip(INITIAL_PUBLIC_BALANCES_FOR_WALLET)
        .collect()
}

#[must_use]
pub fn default_private_accounts_for_wallet() -> Vec<InitialPrivateAccountForWallet> {
    let mut key_chains = vec![KeyChain::new_os_random(), KeyChain::new_os_random()];
    key_chains.sort_unstable();

    key_chains
        .into_iter()
        .zip(INITIAL_PRIVATE_BALANCES_FOR_WALLET)
        .map(|(key_chain, balance)| InitialPrivateAccountForWallet {
            key_chain,
            identifier: 0,
            balance,
        })
        .collect()
}

#[must_use]
pub fn genesis_from_accounts(
    public_accounts: &[(PrivateKey, u128)],
    private_accounts: &[InitialPrivateAccountForWallet],
) -> Vec<GenesisAction> {
    let public_genesis = public_accounts.iter().map(|(private_key, balance)| {
        let public_key = PublicKey::new_from_private_key(private_key);
        let account_id = AccountId::from(&public_key);
        GenesisAction::SupplyAccount {
            account_id,
            balance: *balance,
        }
    });

    let private_genesis = private_accounts
        .iter()
        .map(|account| GenesisAction::SupplyAccount {
            account_id: account.account_id(),
            balance: account.balance,
        });

    public_genesis.chain(private_genesis).collect()
}

pub fn wallet_config(sequencer_addr: SocketAddr) -> Result<WalletConfig> {
    Ok(WalletConfig {
        sequencer_addr: addr_to_url(UrlProtocol::Http, sequencer_addr)
            .context("Failed to convert sequencer addr to URL")?,
        seq_poll_timeout: Duration::from_secs(30),
        seq_tx_poll_max_blocks: 15,
        seq_poll_max_retries: 10,
        seq_block_poll_max_amount: 100,
        basic_auth: None,
    })
}

pub fn indexer_config(bedrock_addr: SocketAddr, home: PathBuf) -> Result<IndexerConfig> {
    Ok(IndexerConfig {
        home,
        consensus_info_polling_interval: Duration::from_secs(1),
        bedrock_config: ClientConfig {
            addr: addr_to_url(UrlProtocol::Http, bedrock_addr)
                .context("Failed to convert bedrock addr to URL")?,
            auth: None,
        },
        channel_id: bedrock_channel_id(),
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
