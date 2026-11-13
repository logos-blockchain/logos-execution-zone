use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::BlockId;
pub use lee_core::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, digest::FixedOutput as _};

use crate::{HashType, transaction::LeeTransaction};
pub type BlockHash = HashType;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockMeta {
    pub id: BlockId,
    pub hash: BlockHash,
}

impl From<&Block> for BlockMeta {
    fn from(block: &Block) -> Self {
        Self {
            id: block.header.block_id,
            hash: block.header.hash,
        }
    }
}

/// The last peer block accepted onto a cross-zone peer chain, and the link the
/// next one has to carry.
///
/// `block_hash` is the recomputed hash, not `header.hash` as read: a block may
/// carry a bogus one and break the link against the peer's next honest block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PeerChainTip {
    pub block_id: u64,
    pub block_hash: HashType,
}

#[derive(Debug, Clone)]
/// Our own hasher.
/// Currently it is SHA256 hasher wrapper. May change in a future.
pub struct OwnHasher;

impl OwnHasher {
    #[must_use]
    pub fn hash(data: &[u8]) -> HashType {
        let mut hasher = Sha256::new();

        hasher.update(data);
        HashType(<[u8; 32]>::from(hasher.finalize_fixed()))
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    pub block_id: BlockId,
    pub prev_block_hash: BlockHash,
    pub hash: BlockHash,
    pub timestamp: Timestamp,
}

/// The fee one transaction paid; all zeros for a fee-exempt one (genesis transactions and exempt
/// shapes). A charged one held a reserve of `fee_base + tip + refund`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct FeeReceipt {
    /// Charged execution gas, including a private proof's verification.
    pub gas_exec: u64,
    /// Charged storage gas.
    pub gas_stor: u64,
    pub fee_base: u128,
    /// For an in-proof fee, also a surplus kept rather than refunded.
    pub tip: u128,
    pub refund: u128,
}

/// The outcome of one user transaction, as its settlement produced it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct TransactionReceipt {
    /// `true`: applied; `false`: the action reverted, and its fee was still charged.
    pub success: bool,
    pub fee: FeeReceipt,
}

impl TransactionReceipt {
    /// A fee-exempt tx, such as system-injected ones.
    pub const EXEMPT: Self = Self {
        success: true,
        fee: FeeReceipt {
            gas_exec: 0,
            gas_stor: 0,
            fee_base: 0,
            tip: 0,
            refund: 0,
        },
    };
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockBody {
    pub transactions: Vec<LeeTransaction>,
    /// One per user transaction, parallel to `transactions`; the trailing fee and clock
    /// transactions have none.
    pub receipts: Vec<TransactionReceipt>,
}

impl BlockBody {
    /// Whether the transaction at `position` reverted.
    #[must_use]
    pub fn is_reverted(&self, position: usize) -> bool {
        self.receipts
            .get(position)
            .is_some_and(|receipt| !receipt.success)
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum BedrockStatus {
    Pending,
    Safe,
    Finalized,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub bedrock_status: BedrockStatus,
}

impl Block {
    /// Recomputes the hash from this block's contents, for integrity verification
    /// against the value stored in `header.hash`.
    #[must_use]
    pub fn recompute_hash(&self) -> BlockHash {
        HashableBlockData {
            block_id: self.header.block_id,
            prev_block_hash: self.header.prev_block_hash,
            timestamp: self.header.timestamp,
            transactions: self.body.transactions.clone(),
            receipts: self.body.receipts.clone(),
        }
        .compute_hash()
    }
}

impl Serialize for Block {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::borsh_base64::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Block {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::borsh_base64::deserialize(deserializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HashableBlockData {
    pub block_id: BlockId,
    pub prev_block_hash: BlockHash,
    pub timestamp: Timestamp,
    pub transactions: Vec<LeeTransaction>,
    /// See [`BlockBody::receipts`].
    pub receipts: Vec<TransactionReceipt>,
}

impl HashableBlockData {
    /// Domain-separated hash of the block contents:
    /// `SHA256(PREFIX || borsh(self))`. The single source of truth for both
    /// producing and verifying a block hash.
    #[must_use]
    pub fn compute_hash(&self) -> BlockHash {
        const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Block/\x00\x00\x00\x00\x00\x00\x00\x00";

        let data_bytes = borsh::to_vec(self).unwrap();
        let mut bytes = Vec::with_capacity(
            PREFIX
                .len()
                .checked_add(data_bytes.len())
                .expect("length overflow"),
        );
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&data_bytes);
        OwnHasher::hash(&bytes)
    }

    #[must_use]
    pub fn into_pending_block(self) -> Block {
        let hash = self.compute_hash();
        Block {
            header: BlockHeader {
                block_id: self.block_id,
                prev_block_hash: self.prev_block_hash,
                hash,
                timestamp: self.timestamp,
            },
            body: BlockBody {
                transactions: self.transactions,
                receipts: self.receipts,
            },
            bedrock_status: BedrockStatus::Pending,
        }
    }
}

impl From<Block> for HashableBlockData {
    fn from(value: Block) -> Self {
        Self {
            block_id: value.header.block_id,
            prev_block_hash: value.header.prev_block_hash,
            timestamp: value.header.timestamp,
            transactions: value.body.transactions,
            receipts: value.body.receipts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TransactionReceipt;
    use crate::{HashType, block::HashableBlockData, test_utils};

    #[test]
    fn encoding_roundtrip() {
        let transactions = vec![test_utils::produce_dummy_empty_transaction()];
        let block = test_utils::produce_dummy_block(1, Some(HashType([1; 32])), transactions);
        let hashable = HashableBlockData::from(block);
        let bytes = borsh::to_vec(&hashable).unwrap();
        let block_from_bytes = borsh::from_slice::<HashableBlockData>(&bytes).unwrap();
        assert_eq!(hashable, block_from_bytes);
    }

    #[test]
    fn recompute_hash_matches_header_for_well_formed_block() {
        let block = HashableBlockData {
            receipts: Vec::new(),
            block_id: 5,
            prev_block_hash: HashType([9_u8; 32]),
            timestamp: 42,
            transactions: vec![test_utils::produce_dummy_empty_transaction()],
        }
        .into_pending_block();
        assert_eq!(block.recompute_hash(), block.header.hash);
    }

    #[test]
    fn recompute_hash_covers_the_receipts() {
        let block = HashableBlockData {
            block_id: 5,
            prev_block_hash: HashType([9_u8; 32]),
            timestamp: 42,
            transactions: vec![test_utils::produce_dummy_empty_transaction()],
            receipts: Vec::new(),
        }
        .into_pending_block();

        let mut listed = block.clone();
        listed.body.receipts.push(TransactionReceipt {
            success: false,
            ..TransactionReceipt::EXEMPT
        });
        assert_ne!(listed.recompute_hash(), block.header.hash);
        assert!(listed.body.is_reverted(0));
        assert!(!block.body.is_reverted(0));
    }

    #[test]
    fn recompute_hash_detects_tampering() {
        let block = HashableBlockData {
            receipts: Vec::new(),
            block_id: 5,
            prev_block_hash: HashType([9_u8; 32]),
            timestamp: 42,
            transactions: vec![test_utils::produce_dummy_empty_transaction()],
        }
        .into_pending_block();

        let mut tampered = block;
        tampered.header.timestamp = 99; // header changed; stale hash no longer matches
        assert_ne!(tampered.recompute_hash(), tampered.header.hash);
    }
}
