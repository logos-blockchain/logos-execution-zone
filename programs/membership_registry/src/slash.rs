use nssa_core::{
    Commitment, NullifierPublicKey, NullifierSecretKey, 
    account::Account,
};

use crate::state::ForumInstance;

pub fn process_slash(
    forum: &mut ForumInstance,
    slashed_nsk: &NullifierSecretKey,
) -> Result<(), &'static str> {
    // 1. Identity Derivation
    let derived_npk = NullifierPublicKey::from(slashed_nsk);
    let expected_commitment = Commitment::new(&derived_npk, &Account::default());

    // 2. Membership Verification
   let comm_bytes = expected_commitment.to_byte_array();
    
    // 3. Double-Slash Check
    if forum.revoked_commitments.contains(&comm_bytes) {
        return Err("Slashing failed: This member's access has already been revoked.");
    }

    // 4. Revocation Execution
    forum.revoked_commitments.push(comm_bytes);
    
    if forum.total_staked >= 1000 {
        forum.total_staked -= 1000;
    }

    Ok(())
}