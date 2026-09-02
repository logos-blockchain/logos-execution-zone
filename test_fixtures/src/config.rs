use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use bytesize::ByteSize;
use indexer_service::{ChannelId, ClientConfig, EventFilterConfig, IndexerConfig};
use key_protocol::key_management::{KeyChain, secret_holders::SeedHolder};
use lee::{AccountId, PrivateKey, PublicKey};
use lee_core::Identifier;
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkPublicKey};
use num_bigint::BigUint;
use sequencer_core::{
    config::{BedrockConfig, CrossZoneConfig, GenesisAction, GossipConfig, SequencerConfig},
    sign_genesis_stake,
};
use sequencer_stake_core::SequencerKey;
use url::Url;
use wallet::config::{MultiSequencerClientConfig, SequencerConnectionData, WalletConfig};

pub const INITIAL_PUBLIC_BALANCES_FOR_WALLET: [u128; 2] = [10_000, 20_000];
pub const INITIAL_PRIVATE_BALANCES_FOR_WALLET: [u128; 2] = [10_000, 20_000];

/// The public account for funding the private accounts' balances at genesis.
pub const PRIVATE_FUNDER_INDEX: usize = 0;

/// Fixed sequencer signing key; exposed so the fixture generator can reopen the produced store.
pub const SEQUENCER_SIGNING_KEY: [u8; 32] = [37; 32];

/// Key of the account holding the sequencer's genesis stake. Separate from
/// [`SEQUENCER_SIGNING_KEY`]: block signing and stake control are distinct roles.
pub const SEQUENCER_STAKE_KEY: [u8; 32] = [55; 32];

/// Bedrock signing key used by the prebuilt dump as first accredited key.
pub const SEQUENCER_BEDROCK_SIGNING_KEY: [u8; 32] = [77; 32];

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
    pub priority_fee_percent: u64,
}

impl Default for SequencerPartialConfig {
    fn default() -> Self {
        Self {
            max_num_tx_in_block: 20,
            max_block_size: ByteSize::mib(1),
            mempool_max_size: 10_000,
            block_create_timeout: Duration::from_secs(10),
            priority_fee_percent: sequencer_core::config::default_priority_fee_percent(),
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
    gossip: Option<GossipConfig>,
) -> Result<SequencerConfig> {
    let SequencerPartialConfig {
        max_num_tx_in_block,
        max_block_size,
        mempool_max_size,
        block_create_timeout,
        priority_fee_percent,
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
            priority_fee_percent,
        },
        cross_zone,
        metrics_address: Some(SequencerConfig::DEFAULT_METRICS_ADDRESS),
        gossip,
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

/// The total value for the shielded pool at genesis.
#[must_use]
pub fn private_total(private_accounts: &[InitialPrivateAccountForWallet]) -> u128 {
    private_accounts.iter().map(|account| account.balance).sum()
}

#[must_use]
pub fn genesis_from_accounts(
    public_accounts: &[(PrivateKey, u128)],
    private_total: u128,
) -> Vec<GenesisAction> {
    let mut balances: Vec<(AccountId, u128)> = public_accounts
        .iter()
        .map(|(private_key, balance)| {
            (
                AccountId::from(&PublicKey::new_from_private_key(private_key)),
                *balance,
            )
        })
        .collect();

    let funder_balance = &mut balances[PRIVATE_FUNDER_INDEX].1;
    *funder_balance = funder_balance
        .checked_add(private_total)
        .expect("private funder genesis balance overflow");

    balances
        .into_iter()
        .map(|(account_id, balance)| GenesisAction::SupplyAccount {
            account_id,
            balance,
        })
        .chain(std::iter::once(GenesisAction::SupplyBridgeAccount {
            balance: 1_000_000,
        }))
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
        peer_block_cache_window: NonZeroU32::new(1024).expect("1024 is nonzero"),
        allow_chain_reset: false,
        event_filter: EventFilterConfig::Archival,
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

/// Seed of the account owning sequencer `index`'s founding stake.
fn founding_stake_owner_seed(index: usize) -> [u8; 32] {
    if index == 0 {
        return SEQUENCER_STAKE_KEY;
    }
    let mut seed = [0x70; 32];
    seed[0] = u8::try_from(index).expect("Test contexts never run enough sequencers to overflow");
    seed
}

/// Key owning sequencer `index`'s founding stake.
pub fn founding_stake_owner_key(index: usize) -> Result<PrivateKey> {
    PrivateKey::try_new(founding_stake_owner_seed(index))
        .context("Failed to build the founding stake ownership key")
}

/// Genesis entries staking every sequencer in `sequencer_signing_keys`, so the
/// creator opens the channel already accrediting all of them.
pub fn genesis_sequencer_stakes(sequencer_signing_keys: &[[u8; 32]]) -> Result<Vec<GenesisAction>> {
    sequencer_signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let public_key = Ed25519Key::from_bytes(signing_key).public_key();
            let sequencer_key = SequencerKey::new(public_key.to_bytes())
                .context("Sequencer signing key is not a valid Ed25519 point")?;
            let owner = founding_stake_owner_key(index)?;
            Ok(GenesisAction::StakeSequencer {
                sequencer_key,
                ownership_public_key: PublicKey::new_from_private_key(&owner),
                stake_signature: sign_genesis_stake(index, sequencer_key, &owner),
            })
        })
        .collect()
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

/// A source-only zone: programs registered, `InitConfig`s emitted, nobody watched.
#[must_use]
pub const fn source_only_cross_zone() -> CrossZoneConfig {
    CrossZoneConfig {
        peers: Vec::new(),
        source_authority: None,
        source_governance: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `fund_private_accounts` drains the private balances out of the funder.
    #[test]
    fn genesis_supplies_the_funder_enough_to_seed_every_private_account() {
        let public_accounts = default_public_accounts_for_wallet();
        let private_accounts = default_private_accounts_for_wallet();
        let private_total = private_total(&private_accounts);
        let genesis = genesis_from_accounts(&public_accounts, private_total);

        let funder = AccountId::from(&PublicKey::new_from_private_key(
            &public_accounts[PRIVATE_FUNDER_INDEX].0,
        ));
        let supplied = |wanted: AccountId| {
            genesis.iter().find_map(|action| match action {
                GenesisAction::SupplyAccount {
                    account_id,
                    balance,
                } if *account_id == wanted => Some(*balance),
                GenesisAction::SupplyAccount { .. }
                | GenesisAction::SupplyBridgeAccount { .. }
                | GenesisAction::SupplyBridgeLockHolding { .. }
                | GenesisAction::StakeSequencer { .. } => None,
            })
        };

        let funder_supply = supplied(funder).expect("the funder is supplied at genesis");
        assert_eq!(
            funder_supply.checked_sub(public_accounts[PRIVATE_FUNDER_INDEX].1),
            Some(private_total),
            "genesis must give the funder its own balance plus every private balance"
        );

        // A private account has no state until the circuit writes its commitment, so a genesis
        // supply at its id would only strand the balance in the public map.
        for account in &private_accounts {
            assert_eq!(supplied(account.account_id()), None);
        }
    }

    #[test]
    fn default_priority_fee_percent_matches_sequencer_default() {
        assert_eq!(
            SequencerPartialConfig::default().priority_fee_percent,
            sequencer_core::config::default_priority_fee_percent()
        );
    }

    #[test]
    fn custom_priority_fee_percent_reaches_bedrock_config() {
        let priority_fee_percent = 20;
        let config = sequencer_config(
            SequencerPartialConfig {
                priority_fee_percent,
                ..SequencerPartialConfig::default()
            },
            PathBuf::from("test-sequencer"),
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            bedrock_channel_id(),
            bedrock_funding_key(),
            Vec::new(),
            None,
            None,
            None,
        )
        .expect("custom priority fee should produce a valid sequencer config");

        assert_eq!(
            config.bedrock_config.priority_fee_percent,
            priority_fee_percent
        );
    }
}
