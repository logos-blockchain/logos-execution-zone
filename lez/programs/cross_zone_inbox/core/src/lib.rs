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

/// A peer zone whose outbox a zone watches for inbound cross-zone messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossZonePeer {
    /// The peer's Bedrock channel; its 32 bytes double as the peer's zone id.
    pub channel_id: ZoneId,
    /// Programs on the local zone a message from this peer is allowed to target.
    pub allowed_targets: Vec<ProgramId>,
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

/// Peer and per-peer target allowlists, plus this inbox's own zone id.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct InboxConfig {
    pub self_zone: ZoneId,
    pub allowed_peers: BTreeMap<ZoneId, ExpectedPubkey>,
    pub allowed_targets: BTreeMap<ZoneId, Vec<ProgramId>>,
}

impl InboxConfig {
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
    AccountId::for_public_pda(&inbox_id, &PdaSeed::new(INBOX_CONFIG_SEED))
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
