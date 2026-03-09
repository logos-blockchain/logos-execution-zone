use borsh::{BorshDeserialize, BorshSerialize};
use nssa::AccountId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, digest::FixedOutput as _};

use crate::{HashType, transaction::NSSATransaction};

pub type MantleMsgId = [u8; 32];
pub type BlockHash = HashType;
pub type BlockId = u64;
pub type TimeStamp = u64;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockMeta {
    pub id: BlockId,
    pub hash: BlockHash,
    pub msg_id: MantleMsgId,
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
    pub timestamp: TimeStamp,
    pub signature: nssa::Signature,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockBody {
    pub transactions: Vec<NSSATransaction>,
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
    pub bedrock_parent_id: MantleMsgId,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HashableBlockData {
    pub block_id: BlockId,
    pub prev_block_hash: BlockHash,
    pub timestamp: TimeStamp,
    pub transactions: Vec<NSSATransaction>,
}

impl HashableBlockData {
    #[must_use]
    pub fn into_pending_block(
        self,
        signing_key: &nssa::PrivateKey,
        bedrock_parent_id: MantleMsgId,
    ) -> Block {
        let data_bytes = borsh::to_vec(&self).unwrap();
        let signature = nssa::Signature::new(signing_key, &data_bytes);
        let hash = OwnHasher::hash(&data_bytes);
        Block {
            header: BlockHeader {
                block_id: self.block_id,
                prev_block_hash: self.prev_block_hash,
                hash,
                timestamp: self.timestamp,
                signature,
            },
            body: BlockBody {
                transactions: self.transactions,
            },
            bedrock_status: BedrockStatus::Pending,
            bedrock_parent_id,
        }
    }

    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        OwnHasher::hash(&borsh::to_vec(&self).unwrap())
    }
}

impl From<Block> for HashableBlockData {
    fn from(value: Block) -> Self {
        Self {
            block_id: value.header.block_id,
            prev_block_hash: value.header.prev_block_hash,
            timestamp: value.header.timestamp,
            transactions: value.body.transactions,
        }
    }
}

/// Helper struct for account (de-)serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInitialData {
    pub account_id: AccountId,
    pub balance: u128,
}

/// Helper struct to (de-)serialize initial commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentsInitialData {
    pub npk: nssa_core::NullifierPublicKey,
    pub account: nssa_core::account::Account,
}

#[cfg(test)]
mod tests {
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
}
