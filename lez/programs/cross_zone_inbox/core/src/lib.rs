use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

/// Source blocks per seen-set shard, so no single seen account grows without bound.
pub const EPOCH_BLOCKS: u64 = 10_000;

const MESSAGE_KEY_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneMsgKey/00000/";
const INBOX_CONFIG_SEED: [u8; 32] = *b"/LEZ/v0.3/CrossZoneInboxCfg/000/";
const INBOX_SEEN_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneInboxSeen/00/";

/// Raw 32-byte zone (channel) id; the host maps it to the zone-sdk `ChannelId`.
pub type ZoneId = [u8; 32];

/// Block-signing public key pinned per peer zone.
pub type ExpectedPubkey = [u8; 32];

/// Content-addressed replay key for a delivered message.
pub type MessageKey = [u8; 32];

/// One delivery a peer is allowed to make: a program on the peer that may emit,
/// paired with the program here it may reach.
///
/// The pair is the unit rather than two independent lists. A bridging peer needs
/// `wrapped_token` reachable, and any emitter that lets its caller choose the
/// target (`ping_sender` does) would otherwise reach it too, minting tokens with
/// no lock behind them. Naming the pair is what stops two separately reasonable
/// entries composing into a route nobody wrote down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CrossZoneRoute {
    /// The program on the peer zone that emitted the message.
    pub src_program_id: ProgramId,
    /// The program on this zone it may be delivered to.
    pub target_program_id: ProgramId,
}

/// A peer zone whose outbox a zone watches for inbound cross-zone messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossZonePeer {
    /// The peer's Bedrock channel; its 32 bytes double as the peer's zone id.
    pub channel_id: ZoneId,
    /// The deliveries this peer may make: which of its programs may emit, and
    /// what each of them may reach here.
    pub allowed_routes: Vec<CrossZoneRoute>,
    /// The peer's block-signing public key, pinned to reject blocks inscribed by
    /// anyone other than that zone's sequencer. `None` skips the check (the
    /// channel signer is still authenticated by the zone-sdk).
    #[serde(default)]
    pub expected_block_signing_pubkey: Option<[u8; 32]>,
}

/// Cross-zone configuration shared by a zone's sequencer (watcher) and indexer
/// (verifier): the peers it reads from Bedrock and, per peer, the local programs
/// they may deliver to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossZoneConfig {
    pub peers: Vec<CrossZonePeer>,
}

/// A finalized outbound message observed on a peer zone, addressed to a program
/// on this zone. The watcher fills it from the peer's block; it is never
/// self-reported by a user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneMessage {
    pub src_zone: ZoneId,
    pub src_block_id: u64,
    pub src_tx_index: u32,
    pub src_program_id: ProgramId,
    pub target_program_id: ProgramId,
    pub payload: Vec<u8>,
    /// Reserved for a future source-state proof; MUST be `None` in v1.
    pub l1_inclusion_witness: Option<Vec<u8>>,
}

/// Per-peer delivery routes, plus this inbox's own zone id.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct InboxConfig {
    pub self_zone: ZoneId,
    /// Which deliveries each peer may make. A peer absent from this map may
    /// deliver nothing.
    pub allowed_routes: BTreeMap<ZoneId, Vec<CrossZoneRoute>>,
}

impl InboxConfig {
    /// Whether `src_zone` may deliver from `src_program_id` to
    /// `target_program_id`. A peer with no routes may deliver nothing.
    #[must_use]
    pub fn permits(
        &self,
        src_zone: &ZoneId,
        src_program_id: ProgramId,
        target_program_id: ProgramId,
    ) -> bool {
        self.allowed_routes
            .get(src_zone)
            .is_some_and(|routes| routes_permit(routes, src_program_id, target_program_id))
    }

    /// Borsh-encoded form stored in the inbox config account.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("InboxConfig serializes")
    }

    /// Decodes an [`InboxConfig`] from account data.
    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

/// The replay keys seen for one `(src_zone, epoch)` shard.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SeenShard(pub BTreeSet<MessageKey>);

impl SeenShard {
    /// Decodes a shard from account data; empty data is an empty shard.
    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        borsh::from_slice(bytes)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SeenShard serializes")
    }

    #[must_use]
    pub fn contains(&self, key: &MessageKey) -> bool {
        self.0.contains(key)
    }

    /// Inserts a key; returns true if it was newly inserted.
    pub fn insert(&mut self, key: MessageKey) -> bool {
        self.0.insert(key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Delivers a finalized peer message to its target program.
    Dispatch(CrossZoneMessage),
    /// Initializes the inbox config account at genesis. Written once, into a
    /// default (unclaimed) config PDA; the guest refuses a non-default pre-state,
    /// so it cannot be re-run to overwrite the allowlists.
    InitConfig(InboxConfig),
}

/// Whether `routes` authorize a delivery from `src_program_id` to
/// `target_program_id`.
///
/// The one place the rule lives. The inbox guest decides with it and the
/// sequencer's watcher drops unroutable messages with it, and those two must
/// agree: a watcher stricter than the guest loses messages silently, and one
/// looser records deliveries the guest will refuse, which production then feeds
/// in and gives up on.
#[must_use]
pub fn routes_permit(
    routes: &[CrossZoneRoute],
    src_program_id: ProgramId,
    target_program_id: ProgramId,
) -> bool {
    routes.iter().any(|route| {
        route.src_program_id == src_program_id && route.target_program_id == target_program_id
    })
}

/// Content-addressed replay key for a delivered message.
///
/// Hashes `(src_zone, src_block_id, src_tx_index)` under a domain separator.
/// Watcher-independent and immune to proof malleability, since it keys on block
/// id plus index rather than a tx hash.
#[must_use]
pub fn message_key(src_zone: &ZoneId, src_block_id: u64, src_tx_index: u32) -> MessageKey {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 76];
    bytes[..32].copy_from_slice(&MESSAGE_KEY_DOMAIN);
    bytes[32..64].copy_from_slice(src_zone);
    bytes[64..72].copy_from_slice(&src_block_id.to_le_bytes());
    bytes[72..].copy_from_slice(&src_tx_index.to_le_bytes());

    Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

/// The config account holding the allowlists.
#[must_use]
pub fn inbox_config_account_id(inbox_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&inbox_id, &inbox_config_seed())
}

/// Seed of the config PDA, exposed so the guest can claim the account when it
/// initializes the config at genesis.
#[must_use]
pub const fn inbox_config_seed() -> PdaSeed {
    PdaSeed::new(INBOX_CONFIG_SEED)
}

/// The seen-set shard for the `(src_zone, epoch)` the message falls in.
#[must_use]
pub fn inbox_seen_shard_account_id(
    inbox_id: ProgramId,
    src_zone: &ZoneId,
    src_block_id: u64,
) -> AccountId {
    AccountId::for_public_pda(&inbox_id, &inbox_seen_shard_seed(src_zone, src_block_id))
}

/// Seed of the seen-shard PDA, exposed so the guest can claim the account.
#[must_use]
pub fn inbox_seen_shard_seed(src_zone: &ZoneId, src_block_id: u64) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let src_epoch = src_block_id.wrapping_div(EPOCH_BLOCKS);
    let mut bytes = [0_u8; 72];
    bytes[..32].copy_from_slice(&INBOX_SEEN_SEED_DOMAIN);
    bytes[32..64].copy_from_slice(src_zone);
    bytes[64..].copy_from_slice(&src_epoch.to_le_bytes());

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn zone(b: u8) -> ZoneId {
        [b; 32]
    }

    fn program(n: u32) -> ProgramId {
        [n; 8]
    }

    /// The route is the pair. Two entries that are each reasonable on their own,
    /// a lock program that may mint and a ping emitter that may reach a
    /// receiver, must not compose into the lock program's target being
    /// reachable from the ping emitter: that emitter lets its caller choose the
    /// target, so it would mint with nothing locked behind it.
    #[test]
    fn a_route_authorizes_one_pair_and_does_not_compose() {
        let lock = program(1);
        let wrapped_token = program(2);
        let ping_sender = program(3);
        let ping_receiver = program(4);

        let mut allowed_routes = BTreeMap::new();
        allowed_routes.insert(
            zone(9),
            vec![
                CrossZoneRoute {
                    src_program_id: lock,
                    target_program_id: wrapped_token,
                },
                CrossZoneRoute {
                    src_program_id: ping_sender,
                    target_program_id: ping_receiver,
                },
            ],
        );
        let config = InboxConfig {
            self_zone: zone(1),
            allowed_routes,
        };

        assert!(config.permits(&zone(9), lock, wrapped_token));
        assert!(config.permits(&zone(9), ping_sender, ping_receiver));

        assert!(
            !config.permits(&zone(9), ping_sender, wrapped_token),
            "an emitter whose caller picks the target must not reach the bridge's target"
        );
        assert!(
            !config.permits(&zone(9), lock, ping_receiver),
            "a route grants its own target, not every target the peer has"
        );
    }

    #[test]
    fn a_peer_with_no_routes_may_deliver_nothing() {
        let config = InboxConfig {
            self_zone: zone(1),
            allowed_routes: BTreeMap::new(),
        };
        assert!(!config.permits(&zone(9), program(1), program(2)));
    }

    #[test]
    fn message_key_is_stable_and_content_addressed() {
        assert_eq!(message_key(&zone(1), 7, 3), message_key(&zone(1), 7, 3));
        assert_ne!(message_key(&zone(1), 7, 3), message_key(&zone(2), 7, 3));
        assert_ne!(message_key(&zone(1), 7, 3), message_key(&zone(1), 8, 3));
        assert_ne!(message_key(&zone(1), 7, 3), message_key(&zone(1), 7, 4));
    }

    #[test]
    fn seen_shards_split_on_epoch_boundary() {
        let id: ProgramId = [9; 8];
        assert_eq!(
            inbox_seen_shard_account_id(id, &zone(1), 0),
            inbox_seen_shard_account_id(id, &zone(1), EPOCH_BLOCKS - 1),
        );
        assert_ne!(
            inbox_seen_shard_account_id(id, &zone(1), EPOCH_BLOCKS - 1),
            inbox_seen_shard_account_id(id, &zone(1), EPOCH_BLOCKS),
        );
    }
}
