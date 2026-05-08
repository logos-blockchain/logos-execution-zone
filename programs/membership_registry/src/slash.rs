use nssa_core::{
    Commitment, NullifierPublicKey, NullifierSecretKey,
    account::Account,
};

use crate::state::ForumInstance;

pub fn process_slash(
    forum: &mut ForumInstance,
    slashed_nsk: &NullifierSecretKey,
) -> Result<u64, &'static str> {
    let derived_npk = NullifierPublicKey::from(slashed_nsk);
    let expected_commitment = Commitment::new(&derived_npk, &Account::default());
    let comm_bytes = expected_commitment.to_byte_array();

    if !forum.registered_commitments.contains(&comm_bytes) {
        return Err("Slashing failed: NSK does not correspond to any registered member.");
    }

    if forum.revoked_commitments.contains(&comm_bytes) {
        return Err("Slashing failed: This member's access has already been revoked.");
    }

    let confiscated = forum.member_stakes.iter()
        .find(|(c, _)| c == &comm_bytes)
        .map(|(_, s)| *s)
        .unwrap_or(0);

    forum.revoked_commitments.push(comm_bytes);

    if forum.total_staked >= confiscated {
        forum.total_staked -= confiscated;
    }

    Ok(confiscated)
}