use nssa::merkle_tree::MerkleTree;
use crate::state::ForumInstance;

pub fn process_initialize(
    k_strikes: u32,
    n_moderators: u32,
    m_moderators: u32,
) -> Result<ForumInstance, &'static str> {
    if n_moderators > m_moderators {
        return Err("Threshold (N) cannot be greater than total moderators (M)");
    }
    if n_moderators == 0 || m_moderators == 0 {
        return Err("Moderator counts must be greater than zero");
    }
    if k_strikes == 0 {
        return Err("K strikes must be at least 1");
    }

    let empty_registry = MerkleTree::with_capacity(1024);

    let new_forum = ForumInstance {
        admin_pubkey: [0; 32], 
        k_strikes,
        n_moderators,
        m_moderators,
        registry: empty_registry,  
        revoked_commitments: Vec::new(),
        total_staked: 0,
    };

    Ok(new_forum)
}