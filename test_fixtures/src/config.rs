use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use bytesize::ByteSize;
use indexer_service::{ChannelId, ClientConfig, IndexerConfig};
use key_protocol::key_management::{KeyChain, secret_holders::SeedHolder};
use lee::{AccountId, PrivateKey, PublicKey};
use lee_core::Identifier;
use logos_blockchain_key_management_system_service::keys::ZkPublicKey;
use num_bigint::BigUint;
use sequencer_core::config::{BedrockConfig, CrossZoneConfig, GenesisAction, SequencerConfig};
use url::Url;
use wallet::config::{MultiSequencerClientConfig, SequencerConnectionData, WalletConfig};

pub const INITIAL_PUBLIC_BALANCES_FOR_WALLET: [u128; 2] = [10_000, 20_000];
pub const INITIAL_PRIVATE_BALANCES_FOR_WALLET: [u128; 2] = [10_000, 20_000];

/// Fixed sequencer signing key; exposed so the fixture generator can reopen the produced store.
pub const SEQUENCER_SIGNING_KEY: [u8; 32] = [37; 32];

// Fixed entropy seeds for the default accounts: deterministic so one prebuilt database is reusable,
// and distinct from the `testnet_initial_state` accounts to avoid depending on / double-funding
// them.
const DEFAULT_PUBLIC_ACCOUNT_SEEDS: [[u8; 32]; 2] = [[0x11; 32], [0x22; 32]];
const DEFAULT_PRIVATE_ACCOUNT_SEEDS: [[u8; 32]; 2] = [[0x33; 32], [0x44; 32]];

#[derive(Clone)]
pub struct InitialPrivateAccountForWallet {
    pub key_chain: KeyChain,
    pub identifier: Identifier,
    pub balance: u128,
}

impl InitialPrivateAccountForWallet {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::from((
            &self.key_chain.nullifier_public_key,
            &self.key_chain.viewing_public_key,
            self.identifier,
        ))
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

#[derive(Debug, Clone, Copy)]
/// Config for test context in multi-node case.
pub struct MultiNodeTestContextConfig {
    pub num_nodes: usize,
    pub bedrock_channel: ChannelId,
}

impl Default for MultiNodeTestContextConfig {
    fn default() -> Self {
        Self {
            num_nodes: 1,
            bedrock_channel: bedrock_channel_id(),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "All fields are necessary and better to keep separate"
)]
pub fn sequencer_config(
    partial: SequencerPartialConfig,
    home: PathBuf,
    bedrock_addr: SocketAddr,
    channel_id: ChannelId,
    funding_key: ZkPublicKey,
    genesis_transactions: Vec<GenesisAction>,
    cross_zone: Option<CrossZoneConfig>,
    signing_key: Option<[u8; 32]>,
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
        signing_key: signing_key.unwrap_or(SEQUENCER_SIGNING_KEY),
        bedrock_config: BedrockConfig {
            channel_id,
            node_url: addr_to_url(UrlProtocol::Http, bedrock_addr)
                .context("Failed to convert bedrock addr to URL")?,
            funding_key,
            auth: None,
            priority_fee: sequencer_core::config::default_priority_fee(),
        },
        cross_zone,
        metrics_address: Some(SequencerConfig::DEFAULT_METRICS_ADDRESS),
    })
}

#[must_use]
pub fn default_public_accounts_for_wallet() -> Vec<(PrivateKey, u128)> {
    let mut private_keys = DEFAULT_PUBLIC_ACCOUNT_SEEDS
        .iter()
        .map(|seed| PrivateKey::try_new(*seed).expect("Fixed public account seed must be valid"))
        .collect::<Vec<_>>();
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
    let mut key_chains = DEFAULT_PRIVATE_ACCOUNT_SEEDS
        .iter()
        .map(|seed| deterministic_private_key_chain(*seed))
        .collect::<Vec<_>>();
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

/// Deterministic [`KeyChain`] from fixed entropy (mirrors `KeyChain::new_os_random`, seeded).
fn deterministic_private_key_chain(entropy: [u8; 32]) -> KeyChain {
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy).expect("32 bytes of entropy is valid for bip39");
    let seed_holder = SeedHolder::from_mnemonic(&mnemonic, "");

    let secret_spending_key = seed_holder.produce_top_secret_key_holder();
    let private_key_holder = secret_spending_key.produce_private_key_holder(None);
    let nullifier_public_key = private_key_holder.generate_nullifier_public_key();
    let viewing_public_key = private_key_holder.generate_viewing_public_key();

    KeyChain {
        secret_spending_key,
        private_key_holder,
        nullifier_public_key,
        viewing_public_key,
    }
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

    let supply_bridge_account = GenesisAction::SupplyBridgeAccount { balance: 1_000_000 };

    public_genesis
        .chain(private_genesis)
        .chain(std::iter::once(supply_bridge_account))
        .collect()
}

pub fn wallet_config(sequencer_addrs: &[SocketAddr]) -> Result<WalletConfig> {
    let mut sequencers = vec![];

    for addr in sequencer_addrs {
        sequencers.push(SequencerConnectionData {
            sequencer_addr: addr_to_url(UrlProtocol::Http, *addr)
                .context("Failed to convert sequencer addr to URL")?,
            basic_auth: None,
        });
    }

    Ok(WalletConfig {
        sequencers,
        seq_poll_timeout: Duration::from_secs(30),
        seq_tx_poll_max_blocks: 15,
        seq_poll_max_retries: 10,
        seq_block_poll_max_amount: 100,
        multi_sequencer_client_config: MultiSequencerClientConfig {
            distribution_limit: 1,
            calibration_limit: 5,
        },
    })
}

pub fn indexer_config(
    bedrock_addr: SocketAddr,
    channel_id: ChannelId,
    cross_zone: Option<CrossZoneConfig>,
) -> Result<IndexerConfig> {
    Ok(IndexerConfig {
        consensus_info_polling_interval: Duration::from_secs(1),
        cross_zone_accept_unverified: Vec::new(),
        bedrock_config: ClientConfig {
            addr: addr_to_url(UrlProtocol::Http, bedrock_addr)
                .context("Failed to convert bedrock addr to URL")?,
            auth: None,
        },
        channel_id,
        cross_zone,
        bridge_lock_holdings: Vec::new(),
        allow_chain_reset: false,
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

#[must_use]
pub fn bedrock_channel_id() -> ChannelId {
    let channel_id: [u8; 32] = [0_u8, 1]
        .repeat(16)
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    ChannelId::from(channel_id)
}

/// A second zone's channel id, distinct from [`bedrock_channel_id`] so two zones
/// settle independently on one shared Bedrock node in the cross-zone tests.
#[must_use]
pub fn bedrock_channel_id_b() -> ChannelId {
    let channel_id: [u8; 32] = [0_u8, 2]
        .repeat(16)
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    ChannelId::from(channel_id)
}

/// Generate sequencer signing key from `u32` number via repeating le bytes 8 times.
#[must_use]
pub fn sequencer_signing_key_from_seed(seed: u32) -> [u8; 32] {
    seed.to_le_bytes()
        .repeat(8)
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

/// Generate bedrock channel id from `u32` number via repeating le bytes 8 times.
///
/// Counting from the end of `u32` to guarantee, that it is different from
/// `sequencer_signing_key_from_seed`.
#[must_use]
pub fn bedrock_channel_id_from_seed(seed: u32) -> ChannelId {
    let channel_id: [u8; 32] =
    // Useless in this case, but will make clippy happy
    u32::MAX.saturating_sub(seed)
        .to_le_bytes()
        .repeat(8)
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    ChannelId::from(channel_id)
}

/// Funding key of the Bedrock test node, matching `funding_pk` in `bedrock/node-config.yaml`.
#[must_use]
pub fn bedrock_funding_key() -> ZkPublicKey {
    const PUBLIC_KEY_HEX: &str = "2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26";

    let bytes = hex::decode(PUBLIC_KEY_HEX).expect("Fixed funding key must be valid hex");
    ZkPublicKey::from(BigUint::from_bytes_le(&bytes))
}
