use nssa_core::Commitment;
use crate::state::ForumInstance;

pub fn process_register(
    forum: &mut ForumInstance,
    new_commitment: Commitment,
    stake_amount: u64,
) -> Result<(), &'static str> {
    if stake_amount < 1000 {
        return Err("Registration failed: Stake amount is below the minimum limit (1000).");
    }

    let value_bytes = new_commitment.to_byte_array();

    if forum.registered_commitments.contains(&value_bytes) {
        return Err("Registration failed: This commitment is already registered.");
    }

    forum.registry.insert(value_bytes);
    forum.registered_commitments.push(value_bytes);
    forum.member_stakes.push((value_bytes, stake_amount));
    forum.total_staked += stake_amount;

    Ok(())
}