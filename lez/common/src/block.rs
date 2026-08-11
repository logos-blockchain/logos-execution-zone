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

#[derive(Debug, Clone)]
/// Our own hasher.
/// Currently it is SHA256 hasher wrapper. May change in a future.
pub struct OwnHasher;

impl OwnHasher {
    fn hash(data: &[u8]) -> HashType {
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
    /// Public key of the sequencer that produced the block. Part of the hashed
    /// content, so `signature` covers it and it cannot be swapped in transit.
    pub producer: lee::PublicKey,
    pub signature: lee::Signature,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockBody {
    pub transactions: Vec<LeeTransaction>,
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
            producer: self.header.producer.clone(),
            transactions: self.body.transactions.clone(),
        }
        .compute_hash()
    }

    /// Recomputes the signed hash from the block contents and checks the header
    /// signature against `expected_pubkey`. Used to pin a peer zone's
    /// block-signing key, so a block inscribed by anyone other than that zone's
    /// sequencer is rejected even if it reached the channel.
    #[must_use]
    pub fn is_signed_by(&self, expected_pubkey: &lee::PublicKey) -> bool {
        self.header
            .signature
            .is_valid_for(&self.recompute_hash().0, expected_pubkey)
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
    /// The producing sequencer's block-signing public key. Hashed with the rest
    /// of the contents, so [`Block::is_signed_by`] only accepts a signature by
    /// this exact key: a relayer cannot re-point the header at another producer
    /// without breaking the hash.
    pub producer: lee::PublicKey,
    pub transactions: Vec<LeeTransaction>,
}

impl HashableBlockData {
    /// Domain-separated hash of the block contents: `SHA256(PREFIX || borsh(self))`.
    /// The single source of truth for both producing and verifying a block hash.
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

    /// Hashes the contents and signs the hash with `signing_key`.
    ///
    /// `signing_key` must be the private key behind `self.producer`; the shared
    /// apply path rejects a block whose signature is not by `header.producer`.
    #[must_use]
    pub fn into_pending_block(self, signing_key: &lee::PrivateKey) -> Block {
        let hash = self.compute_hash();
        let signature = lee::Signature::new(signing_key, &hash.0);
        Block {
            header: BlockHeader {
                block_id: self.block_id,
                prev_block_hash: self.prev_block_hash,
                hash,
                timestamp: self.timestamp,
                producer: self.producer,
                signature,
            },
            body: BlockBody {
                transactions: self.transactions,
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
            producer: value.header.producer,
            transactions: value.body.transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        HashType,
        block::{Block, HashableBlockData},
        test_utils,
    };

    #[test]
    fn encoding_roundtrip() {
        let transactions = vec![test_utils::produce_dummy_empty_transaction()];
        let block = test_utils::produce_dummy_block(1, Some(HashType([1; 32])), transactions);
        let hashable = HashableBlockData::from(block);
        let bytes = borsh::to_vec(&hashable).unwrap();
        let block_from_bytes = borsh::from_slice::<HashableBlockData>(&bytes).unwrap();
        assert_eq!(hashable, block_from_bytes);
    }

    fn block_signed_by(key: &lee::PrivateKey) -> Block {
        HashableBlockData {
            block_id: 5,
            prev_block_hash: HashType([9_u8; 32]),
            timestamp: 42,
            producer: lee::PublicKey::new_from_private_key(key),
            transactions: vec![test_utils::produce_dummy_empty_transaction()],
        }
        .into_pending_block(key)
    }

    #[test]
    fn recompute_hash_matches_header_for_well_formed_block() {
        let key = lee::PrivateKey::try_new([7_u8; 32]).expect("valid key");
        let block = block_signed_by(&key);
        assert_eq!(block.recompute_hash(), block.header.hash);
    }

    #[test]
    fn recompute_hash_detects_tampering() {
        let key = lee::PrivateKey::try_new([7_u8; 32]).expect("valid key");
        let mut tampered = block_signed_by(&key);
        tampered.header.timestamp = 99; // header changed; stale hash no longer matches
        assert_ne!(tampered.recompute_hash(), tampered.header.hash);
    }

    #[test]
    fn block_is_signed_by_its_producer() {
        let key = lee::PrivateKey::try_new([7_u8; 32]).expect("valid key");
        let block = block_signed_by(&key);
        assert!(block.is_signed_by(&block.header.producer));
    }

    #[test]
    fn recompute_hash_detects_producer_tampering() {
        let key = lee::PrivateKey::try_new([7_u8; 32]).expect("valid key");
        let other = lee::PrivateKey::try_new([8_u8; 32]).expect("valid key");
        let mut tampered = block_signed_by(&key);

        // Re-pointing the header at another producer is what a relayer would do
        // to have the payout credited elsewhere; the producer is hashed, so the
        // stored hash (and with it the signature) no longer matches.
        tampered.header.producer = lee::PublicKey::new_from_private_key(&other);
        assert_ne!(tampered.recompute_hash(), tampered.header.hash);
        assert!(!tampered.is_signed_by(&tampered.header.producer));
    }
}
