use borsh::{BorshDeserialize, BorshSerialize};
use nssa::merkle_tree::MerkleTree; 

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct ForumInstance {
    pub admin_pubkey: [u8; 32],
    pub k_strikes: u32,
    pub n_moderators: u32,
    pub m_moderators: u32,
    pub registry: MerkleTree, 
    pub revoked_commitments: Vec<[u8; 32]>,
    pub total_staked: u64,
}