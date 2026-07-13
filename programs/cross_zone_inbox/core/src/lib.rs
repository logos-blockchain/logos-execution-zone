use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

/// Raw 32-byte zone (channel) id; the host maps it to the zone-sdk `ChannelId`.
pub type ZoneId = [u8; 32];

/// Block-signing public key pinned per peer zone.
pub type ExpectedPubkey = [u8; 32];

/// Content-addressed replay key for a delivered message.
pub type MessageKey = [u8; 32];

/// Source blocks per seen-set shard, so no single seen account grows without bound.
pub const EPOCH_BLOCKS: u64 = 10_000;

const MESSAGE_KEY_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneMsgKey/00000/";
const INBOX_CONFIG_SEED: [u8; 32] = *b"/LEZ/v0.3/CrossZoneInboxCfg/000/";
const INBOX_SEEN_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneInboxSeen/00/";

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

/// Content-addressed replay key: `(src_zone, src_block_id, src_tx_index)` hashed
/// under a domain separator. Watcher-independent and immune to proof
/// malleability, since it keys on block id plus index rather than a tx hash.
#[must_use]
pub fn message_key(src_zone: &ZoneId, src_block_id: u64, src_tx_index: u32) -> MessageKey {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = Vec::with_capacity(MESSAGE_KEY_DOMAIN.len() + 32 + 8 + 4);
    bytes.extend_from_slice(&MESSAGE_KEY_DOMAIN);
    bytes.extend_from_slice(src_zone);
    bytes.extend_from_slice(&src_block_id.to_le_bytes());
    bytes.extend_from_slice(&src_tx_index.to_le_bytes());

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

    let src_epoch = src_block_id / EPOCH_BLOCKS;
    let mut bytes = Vec::with_capacity(INBOX_SEEN_SEED_DOMAIN.len() + 32 + 8);
    bytes.extend_from_slice(&INBOX_SEEN_SEED_DOMAIN);
    bytes.extend_from_slice(src_zone);
    bytes.extend_from_slice(&src_epoch.to_le_bytes());

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

/// Builds the sequencer-origin dispatch transaction. Pure, so the watcher's
/// injected tx and the indexer's re-derived tx are byte-identical for the same
/// inputs (the basis of the Option B check). `target_account_ids` are the
/// inbox's chained-call targets; deriving them is target-specific.
#[cfg(feature = "host")]
#[must_use]
pub fn build_inbox_dispatch_tx(
    inbox_id: ProgramId,
    msg: &CrossZoneMessage,
    target_account_ids: Vec<AccountId>,
) -> lee::PublicTransaction {
    let mut account_ids = Vec::with_capacity(2 + target_account_ids.len());
    account_ids.push(inbox_config_account_id(inbox_id));
    account_ids.push(inbox_seen_shard_account_id(
        inbox_id,
        &msg.src_zone,
        msg.src_block_id,
    ));
    account_ids.extend(target_account_ids);

    let message = lee::public_transaction::Message::try_new(
        inbox_id,
        account_ids,
        vec![],
        Instruction::Dispatch(msg.clone()),
    )
    .expect("inbox dispatch instruction must serialize");

    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

/// The cross-zone emission fields a watcher or verifier reads off a source
/// transaction, common to every emitter program.
#[cfg(feature = "host")]
pub struct Emission {
    pub target_zone: ZoneId,
    pub target_program_id: ProgramId,
    pub target_accounts: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
}

/// Extracts the cross-zone emission from a source transaction, recognizing the
/// known emitter programs. Returns `None` for any other program. The watcher and
/// verifier both use this so they agree on what a given source tx emits.
///
/// Option A: each emitter is decoded explicitly. The principled alternative is to
/// read the outbox PDA write, which would need re-execution of the source tx.
#[cfg(feature = "host")]
#[must_use]
pub fn extract_emission(
    program_id: ProgramId,
    instruction_data: &[u32],
    ping_sender_id: ProgramId,
    bridge_lock_id: ProgramId,
) -> Option<Emission> {
    if program_id == ping_sender_id {
        let ping_core::SenderInstruction::Send {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ..
        } = risc0_zkvm::serde::from_slice(instruction_data).ok()?;
        Some(Emission {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
        })
    } else if program_id == bridge_lock_id {
        let bridge_lock_core::Instruction::Lock {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ..
        } = risc0_zkvm::serde::from_slice(instruction_data).ok()?;
        Some(Emission {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
        })
    } else {
        None
    }
}

/// Builds the dispatch transaction for one peer emission. Both the sequencer's
/// watcher and the indexer's verifier go through this so their transactions are
/// byte-identical for the same emission (the basis of the Option B check).
#[cfg(feature = "host")]
#[must_use]
pub fn build_dispatch_from_emission(
    inbox_id: ProgramId,
    src_zone: ZoneId,
    src_block_id: u64,
    src_tx_index: u32,
    src_program_id: ProgramId,
    target_program_id: ProgramId,
    target_accounts: &[[u8; 32]],
    payload: Vec<u8>,
) -> lee::PublicTransaction {
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_tx_index,
        src_program_id,
        target_program_id,
        payload,
        l1_inclusion_witness: None,
    };
    let target_ids = target_accounts
        .iter()
        .copied()
        .map(AccountId::new)
        .collect();
    build_inbox_dispatch_tx(inbox_id, &msg, target_ids)
}

/// Builds the inbox config account a zone seeds into genesis state so the inbox
/// guest can authorize inbound peer messages. The sequencer and indexer seed the
/// same account from the same config, keeping their replayed state consistent.
#[cfg(feature = "host")]
#[must_use]
pub fn build_inbox_config_account(
    self_zone: ZoneId,
    cross_zone: &CrossZoneConfig,
) -> (AccountId, lee_core::account::Account) {
    let inbox_id = lee::program::Program::cross_zone_inbox().id();

    let mut allowed_targets = BTreeMap::new();
    for peer in &cross_zone.peers {
        allowed_targets.insert(peer.channel_id, peer.allowed_targets.clone());
    }
    let config = InboxConfig {
        self_zone,
        allowed_peers: BTreeMap::new(),
        allowed_targets,
    };

    let account = lee_core::account::Account {
        program_owner: inbox_id,
        balance: 0,
        data: config
            .to_bytes()
            .try_into()
            .expect("inbox config fits in account data"),
        nonce: 0_u128.into(),
    };
    (inbox_config_account_id(inbox_id), account)
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

    #[cfg(feature = "host")]
    #[test]
    fn build_inbox_dispatch_tx_is_deterministic() {
        let inbox: ProgramId = [5; 8];
        let msg = CrossZoneMessage {
            src_zone: zone(1),
            src_block_id: 42,
            src_tx_index: 2,
            src_program_id: [6; 8],
            target_program_id: [7; 8],
            payload: vec![1, 2, 3, 4],
            l1_inclusion_witness: None,
        };
        let targets = vec![AccountId::new([8; 32]), AccountId::new([9; 32])];

        let tx1 = build_inbox_dispatch_tx(inbox, &msg, targets.clone());
        let tx2 = build_inbox_dispatch_tx(inbox, &msg, targets);
        assert_eq!(tx1, tx2);
    }
}
