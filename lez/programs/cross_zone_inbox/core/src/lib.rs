use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

const MESSAGE_KEY_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneMsgKey/00000/";
const INBOX_CONFIG_SEED: [u8; 32] = *b"/LEZ/v0.3/CrossZoneInboxCfg/000/";
/// `/01/` because `/00/` keyed shards by epoch: an epoch and a block id are
/// indistinguishable under one domain. Belt and braces, since the image id
/// already relocates every PDA in this crate whenever the crate changes.
const INBOX_SEEN_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneInboxSeen/01/";

/// Raw 32-byte zone (channel) id; the host maps it to the zone-sdk `ChannelId`.
pub type ZoneId = [u8; 32];

/// Block-signing public key pinned per peer zone.
pub type ExpectedPubkey = [u8; 32];

/// Content-addressed replay key for a delivered message.
pub type MessageKey = [u8; 32];

/// One delivery a peer is allowed to make: a program on the peer that may emit,
/// paired with the program here it may reach.
///
/// The pair is the unit because the target authorizes a source, not a zone. A
/// bridging peer needs `wrapped_token` reachable, and `ping_sender` lets its
/// caller choose the target, so a zone-wide allowance would let it mint with no
/// lock behind it. That rule now lives in each target, seeded from these pairs at
/// genesis, rather than in the inbox.
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
    /// Which of this peer's programs may reach which local program.
    ///
    /// No longer enforced in transit: the inbox delivers to whatever a message
    /// names, and the target refuses a source it did not authorize. This is the
    /// operator's statement of intent, fanned out at genesis into each target's
    /// own config. A route naming a program that does not authorize cross-zone
    /// sources is refused there, at genesis.
    pub allowed_routes: Vec<CrossZoneRoute>,
    /// The peer's block-signing public key, pinned to reject blocks inscribed by
    /// anyone other than that zone's sequencer. `None` skips the check (the
    /// channel signer is still authenticated by the zone-sdk).
    #[serde(default)]
    pub expected_block_signing_pubkey: Option<[u8; 32]>,
}

/// Cross-zone configuration shared by a zone's sequencer (watcher) and indexer
/// (verifier): the peers it reads from Bedrock and, per peer, the deliveries the
/// operator intends each target to accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossZoneConfig {
    /// Read once at startup by the watchers and the verifier, so adding a peer
    /// zone needs a config change and a restart on both sequencer and indexer.
    pub peers: Vec<CrossZonePeer>,
    /// Account allowed to change which peer sources each target program accepts,
    /// seeded into every target's own config at genesis.
    ///
    /// Unset by default, which leaves those lists fixed at genesis. It can only
    /// ever be set at genesis and there is no rotation. One value seeds every
    /// target, including the ones that mint, and whoever holds it can authorize
    /// a source, so its compromise is theft rather than delay.
    ///
    /// Must be a fresh, never-used account: the first use has the target claim
    /// it, renouncing seizes it the same way, whichever target acts first owns
    /// it, and anything sent to it is frozen for good. An `AccountId` rather
    /// than a key so a governance program's PDA can hold it later.
    #[serde(default)]
    pub source_authority: Option<AccountId>,
    /// Program allowed to act on the source authority's behalf through a chained
    /// call, seeded into every target's config at genesis. Needed only for a PDA
    /// authority, which cannot sign; unset means the authority acts at top level.
    #[serde(default)]
    pub source_governance: Option<ProgramId>,
}

/// A finalized outbound message observed on a peer zone, addressed to a program
/// on this zone. The watcher fills it from the peer's block; it is never
/// self-reported by a user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneMessage {
    pub src_zone: ZoneId,
    pub src_block_id: u64,
    /// The source block's recomputed hash, never the `header.hash` it declares.
    ///
    /// The signature does not cover that field, so a correctly signed block can
    /// carry a bogus one. Both the watcher and the verifier hash the block's
    /// contents themselves and fill this from that, so the two agree on it
    /// without either trusting what the peer wrote.
    pub src_block_hash: [u8; 32],
    pub src_tx_index: u32,
    pub src_program_id: ProgramId,
    pub target_program_id: ProgramId,
    pub payload: Vec<u8>,
    /// Reserved for a future source-state proof; MUST be `None` in v1.
    pub l1_inclusion_witness: Option<Vec<u8>>,
}

/// This inbox's own zone id.
///
/// It no longer decides who may deliver what. Each target program authorizes its
/// own sources against the marker the inbox passes, so the only thing the inbox
/// still needs to know is which zone it is, to refuse a message addressed to
/// itself.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct InboxConfig {
    pub self_zone: ZoneId,
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

/// What one peer block has already delivered.
///
/// Indices, not message keys: the shard's address already binds
/// `(src_zone, src_block_id)`, so a key stored inside it adds nothing.
///
/// A shard costs an account plus a 36-byte header and breaks even against a
/// shared shard at about five deliveries. What that buys is saturation
/// resistance: at 32 bytes per delivery one peer block could overflow the
/// account, and the guest's only answer is a panic that costs the message.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SeenShard {
    /// Recomputed hash of the peer block this shard records deliveries from.
    /// All-zero until the first delivery claims it.
    pub src_block_hash: [u8; 32],
    /// Indices of that block's transactions already delivered.
    pub delivered: BTreeSet<u32>,
}

impl SeenShard {
    /// Deliveries one shard can hold before it exceeds `DATA_MAX_LENGTH`.
    ///
    /// Borsh is 32 bytes of hash, a 4-byte count, then 4 bytes per index, so
    /// this is exactly the 100 KiB an account may carry.
    ///
    /// Out of reach only because of the L1 inscription cap: a block inscribes as
    /// one op near 1.75 MiB and a minimal emitting transaction is about 257
    /// bytes, capping a peer block near 7,100 deliveries. Raising that L1 cap
    /// past roughly 6.3 MiB puts this back in reach.
    pub const MAX_DELIVERIES: usize = 25_591;

    /// Decodes a shard from account data; empty data is an unclaimed shard.
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

    /// Whether a delivery from the block with this hash may be recorded here.
    ///
    /// An unclaimed shard binds to its first claimant. Unclaimed is the whole
    /// value being default, not the hash being zero, so a shard holding any
    /// delivery can never read as unclaimed.
    #[must_use]
    pub fn binds(&self, src_block_hash: &[u8; 32]) -> bool {
        *self == Self::default() || self.src_block_hash == *src_block_hash
    }

    #[must_use]
    pub fn contains(&self, src_tx_index: u32) -> bool {
        self.delivered.contains(&src_tx_index)
    }

    /// Binds the shard if unclaimed and records the delivery; true if new.
    ///
    /// A non-binding hash records nothing. The guest already asserts
    /// [`Self::binds`], so this is a backstop against a future caller rebinding
    /// a claimed shard and erasing which peer block delivered what.
    pub fn insert(&mut self, src_block_hash: [u8; 32], src_tx_index: u32) -> bool {
        if !self.binds(&src_block_hash) {
            return false;
        }
        self.src_block_hash = src_block_hash;
        self.delivered.insert(src_tx_index)
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

/// The seen-set shard for the peer block the message came from.
#[must_use]
pub fn inbox_seen_shard_account_id(
    inbox_id: ProgramId,
    src_zone: &ZoneId,
    src_block_id: u64,
) -> AccountId {
    AccountId::for_public_pda(&inbox_id, &inbox_seen_shard_seed(src_zone, src_block_id))
}

/// Seed of the seen-shard PDA, exposed so the guest can claim the account.
///
/// One shard per peer block, so a peer cannot accumulate deliveries from many
/// blocks into one account.
#[must_use]
pub fn inbox_seen_shard_seed(src_zone: &ZoneId, src_block_id: u64) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 72];
    bytes[..32].copy_from_slice(&INBOX_SEEN_SEED_DOMAIN);
    bytes[32..64].copy_from_slice(src_zone);
    bytes[64..].copy_from_slice(&src_block_id.to_le_bytes());

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

#[cfg(test)]
mod tests {
    use lee_core::account::data::DATA_MAX_LENGTH;

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
    fn every_peer_block_gets_its_own_seen_shard() {
        let id: ProgramId = [9; 8];
        assert_eq!(
            inbox_seen_shard_account_id(id, &zone(1), 7),
            inbox_seen_shard_account_id(id, &zone(1), 7),
        );
        assert_ne!(
            inbox_seen_shard_account_id(id, &zone(1), 7),
            inbox_seen_shard_account_id(id, &zone(1), 8),
        );
        assert_ne!(
            inbox_seen_shard_account_id(id, &zone(1), 7),
            inbox_seen_shard_account_id(id, &zone(2), 7),
        );
    }

    #[test]
    fn a_shard_binds_to_the_first_block_that_claims_it() {
        let mut shard = SeenShard::default();
        assert!(shard.binds(&[1; 32]), "an unclaimed shard binds to anyone");
        assert!(shard.binds(&[2; 32]));

        shard.insert([1; 32], 0);
        assert!(shard.binds(&[1; 32]), "and to that block thereafter");
        assert!(
            !shard.binds(&[2; 32]),
            "a second block claiming the same block id cannot share this shard"
        );
    }

    #[test]
    fn a_shard_records_deliveries_by_transaction_index() {
        let mut shard = SeenShard::default();
        assert!(!shard.contains(3));
        assert!(shard.insert([1; 32], 3));
        assert!(shard.contains(3));
        assert!(
            !shard.insert([1; 32], 3),
            "a replay of the same delivery records nothing new"
        );
        assert!(shard.insert([1; 32], 4));
    }

    #[test]
    fn an_unclaimed_shard_reads_as_empty_and_round_trips() {
        assert_eq!(
            SeenShard::from_bytes(&[]).expect("empty data decodes"),
            SeenShard::default(),
            "an absent account is an unclaimed shard, not a decode failure"
        );

        let mut shard = SeenShard::default();
        shard.insert([5; 32], 1);
        shard.insert([5; 32], 9);
        assert_eq!(
            SeenShard::from_bytes(&shard.to_bytes()).expect("shard decodes"),
            shard
        );
    }

    #[test]
    fn a_full_shard_fits_in_account_data() {
        let mut shard = SeenShard::default();
        for index in 0..SeenShard::MAX_DELIVERIES {
            shard.insert([5; 32], u32::try_from(index).expect("index fits"));
        }
        let max = usize::try_from(DATA_MAX_LENGTH.as_u64()).expect("cap fits in usize");
        assert_eq!(
            shard.to_bytes().len(),
            max,
            "MAX_DELIVERIES is exactly what an account can carry"
        );

        shard.insert(
            [5; 32],
            u32::try_from(SeenShard::MAX_DELIVERIES).expect("index fits"),
        );
        assert!(
            shard.to_bytes().len() > max,
            "and one more does not fit, so the guest would fail rather than truncate"
        );
    }
}
