use borsh::{BorshDeserialize, BorshSerialize};
use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};
use lee_core::BlockId;
pub use lee_core::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, digest::FixedOutput as _};

use crate::{
    HashType,
    transaction::{LeeTransaction, LeeTransactionWith},
};
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

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    pub block_id: BlockId,
    pub prev_block_hash: BlockHash,
    pub hash: BlockHash,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockBodyWith<P> {
    pub transactions: Vec<LeeTransactionWith<P>>,
    /// Indices into `transactions` of the charged transactions whose action reverted, ascending.
    ///
    /// TODO: fold into a `receipts` vector parallel to `transactions`, one per transaction with
    /// its status and fee charged, once receipts are exposed.
    pub reverted: Vec<u64>,
}

pub type BlockBody = BlockBodyWith<Proof>;

impl<P> BlockBodyWith<P> {
    /// Whether the transaction at `position` reverted.
    #[must_use]
    pub fn is_reverted(&self, position: usize) -> bool {
        // note: `contains` here is not too expensive,
        // we don't expect many reverted tx'es every block
        u64::try_from(position).is_ok_and(|position| self.reverted.contains(&position))
    }

    pub fn proofs(&self) -> impl Iterator<Item = &P> {
        self.transactions.iter().filter_map(LeeTransactionWith::proof)
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
    #[must_use]
    pub fn digested(&self) -> DigestedBlock {
        DigestedBlock {
            header: self.header.clone(),
            body: BlockBodyWith {
                transactions: self
                    .body
                    .transactions
                    .iter()
                    .map(LeeTransaction::digested)
                    .collect(),
                reverted: self.body.reverted.clone(),
            },
        }
    }

    /// Recomputes the hash from this block's contents, for integrity verification
    /// against the value stored in `header.hash`.
    #[must_use]
    pub fn recompute_hash(&self) -> BlockHash {
        self.digested().recompute_hash()
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
pub struct DigestedBlock {
    pub header: BlockHeader,
    pub body: BlockBodyWith<ProofDigest>,
}

impl DigestedBlock {
    #[must_use]
    pub fn recompute_hash(&self) -> BlockHash {
        HashableBlockDataWith {
            block_id: self.header.block_id,
            prev_block_hash: self.header.prev_block_hash,
            timestamp: self.header.timestamp,
            transactions: self.body.transactions.clone(),
            reverted: self.body.reverted.clone(),
        }
        .compute_hash()
    }

    pub fn to_inscription(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    pub fn from_inscription(bytes: &[u8]) -> std::io::Result<Self> {
        borsh::from_slice(bytes)
    }

    pub fn hydrate(&self, proofs: impl Fn(&ProofDigest) -> Option<Proof>) -> Option<Block> {
        let transactions = self
            .body
            .transactions
            .iter()
            .map(|transaction| match transaction {
                LeeTransactionWith::Public(tx) => Some(LeeTransaction::Public(tx.clone())),
                LeeTransactionWith::PrivacyPreserving(tx) => proofs(tx.witness_set().proof())
                    .and_then(|proof| tx.hydrate(proof))
                    .map(LeeTransaction::PrivacyPreserving),
            })
            .collect::<Option<_>>()?;
        Some(Block {
            header: self.header.clone(),
            body: BlockBody {
                transactions,
                reverted: self.body.reverted.clone(),
            },
            bedrock_status: BedrockStatus::Pending,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HashableBlockDataWith<P> {
    pub block_id: BlockId,
    pub prev_block_hash: BlockHash,
    pub timestamp: Timestamp,
    pub transactions: Vec<LeeTransactionWith<P>>,
    /// See [`BlockBody::reverted`].
    pub reverted: Vec<u64>,
}

pub type HashableBlockData = HashableBlockDataWith<Proof>;

impl HashableBlockDataWith<ProofDigest> {
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
}

impl HashableBlockData {
    #[must_use]
    pub fn compute_hash(&self) -> BlockHash {
        HashableBlockDataWith {
            block_id: self.block_id,
            prev_block_hash: self.prev_block_hash,
            timestamp: self.timestamp,
            transactions: self
                .transactions
                .iter()
                .map(LeeTransaction::digested)
                .collect(),
            reverted: self.reverted.clone(),
        }
        .compute_hash()
    }

    #[must_use]
    pub fn into_pending_block(self) -> Block {
        let hash = self.compute_hash();
        self.into_block(hash)
    }

    pub fn inscription_len(self) -> std::io::Result<usize> {
        // The hash is fixed-width, so its value does not change the length.
        borsh::object_length(&self.into_block(HashType([0; 32])).digested())
    }

    fn into_block(self, hash: BlockHash) -> Block {
        Block {
            header: BlockHeader {
                block_id: self.block_id,
                prev_block_hash: self.prev_block_hash,
                hash,
                timestamp: self.timestamp,
            },
            body: BlockBody {
                transactions: self.transactions,
                reverted: self.reverted,
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
            reverted: value.body.reverted,
        }
    }
}

#[cfg(test)]
mod tests {
    use lee::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{Message, WitnessSet, circuit::Proof},
    };

    use crate::{
        HashType,
        block::{DigestedBlock, HashableBlockData, HashableBlockDataWith, OwnHasher},
        test_utils,
        transaction::LeeTransaction,
    };

    fn private_transaction(proof: Vec<u8>) -> LeeTransaction {
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            Message::default(),
            WitnessSet::from_raw_parts(vec![], Proof::from_inner(proof)),
        ))
    }

    fn non_repeating_proof() -> Vec<u8> {
        (0..=u8::MAX)
            .flat_map(|n| OwnHasher::hash(&[n]).0)
            .collect()
    }

    fn block_data_with(transactions: Vec<LeeTransaction>) -> HashableBlockData {
        HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            transactions,
            reverted: Vec::new(),
        }
    }

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
            reverted: Vec::new(),
            block_id: 5,
            prev_block_hash: HashType([9_u8; 32]),
            timestamp: 42,
            transactions: vec![test_utils::produce_dummy_empty_transaction()],
        }
        .into_pending_block();
        assert_eq!(block.recompute_hash(), block.header.hash);
    }

    #[test]
    fn recompute_hash_covers_the_reverted_list() {
        let block = HashableBlockData {
            block_id: 5,
            prev_block_hash: HashType([9_u8; 32]),
            timestamp: 42,
            transactions: vec![test_utils::produce_dummy_empty_transaction()],
            reverted: Vec::new(),
        }
        .into_pending_block();

        let mut listed = block.clone();
        listed.body.reverted.push(0);
        assert_ne!(listed.recompute_hash(), block.header.hash);
        assert!(listed.body.is_reverted(0));
        assert!(!block.body.is_reverted(0));
    }

    #[test]
    fn recompute_hash_detects_tampering() {
        let block = HashableBlockData {
            reverted: Vec::new(),
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

    #[test]
    fn the_block_hash_is_the_tagged_sha256_of_the_digest_form() {
        let data = block_data_with(vec![
            private_transaction(vec![0; 32]),
            test_utils::produce_dummy_empty_transaction(),
        ]);
        let digest_form = HashableBlockDataWith {
            block_id: data.block_id,
            prev_block_hash: data.prev_block_hash,
            timestamp: data.timestamp,
            transactions: data
                .transactions
                .iter()
                .map(LeeTransaction::digested)
                .collect(),
            reverted: data.reverted.clone(),
        };
        let tag = b"/LEE/v0.3/Message/Block/\x00\x00\x00\x00\x00\x00\x00\x00";
        let expected = OwnHasher::hash(&[&tag[..], &borsh::to_vec(&digest_form).unwrap()].concat());

        assert_eq!(digest_form.compute_hash(), expected);
        assert_eq!(data.compute_hash(), expected);
        assert_eq!(data.into_pending_block().recompute_hash(), expected);
    }

    #[test]
    fn the_transaction_and_block_hashes_commit_to_each_proof() {
        let hashes_with = |proof: Vec<u8>| {
            let tx = private_transaction(proof);
            (tx.hash(), block_data_with(vec![tx]).compute_hash())
        };

        assert_eq!(hashes_with(vec![0; 32]), hashes_with(vec![0; 32]));
        let (tx_hash, block_hash) = hashes_with(vec![0; 32]);
        let (other_tx_hash, other_block_hash) = hashes_with(vec![1; 32]);
        assert_ne!(tx_hash, other_tx_hash);
        assert_ne!(block_hash, other_block_hash);
    }

    #[test]
    fn a_private_blocks_inscription_round_trips_carrying_its_proof_digest_and_none_of_its_bytes() {
        let proof = non_repeating_proof();
        let digest = Proof::from_inner(proof.clone()).digest();
        let block = block_data_with(vec![
            private_transaction(proof.clone()),
            test_utils::produce_dummy_empty_transaction(),
        ])
        .into_pending_block()
        .digested();

        let inscription = block.to_inscription().unwrap();

        let decoded = DigestedBlock::from_inscription(&inscription).unwrap();
        assert_eq!(decoded, block);
        assert!(decoded.body.proofs().eq([&digest]));
        assert!(inscription.len() < proof.len());
        let distinctive = &proof[4096..4128];
        assert!(
            !inscription
                .windows(distinctive.len())
                .any(|window| window == distinctive)
        );
    }

    #[test]
    fn inscription_len_is_the_length_of_the_inscribed_block_not_of_its_full_form() {
        let data = HashableBlockData {
            reverted: vec![0],
            ..block_data_with(vec![
                private_transaction(non_repeating_proof()),
                test_utils::produce_dummy_empty_transaction(),
            ])
        };
        let block = data.clone().into_pending_block();
        let inscribed = block.digested().to_inscription().unwrap();

        let measured = data.inscription_len().unwrap();

        assert_eq!(measured, inscribed.len());
        assert!(measured < borsh::to_vec(&block).unwrap().len());
    }
}
