//! Clock Program.
//!
//! A system program that records the current block ID and timestamp into dedicated clock accounts.
//! Three accounts are maintained, updated at different block intervals (every 1, 10, and 50
//! blocks), allowing programs to read recent timestamps at various granularities.
//!
//! Only the sequencer may invoke this program, as the last transaction in every block.
//! Each clock account uses this program's shard.

use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData, Instruction,
};
use lee_core::program::{Plan, PlanInput, run_program};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    Advance(ClockAccountData),
    Record(ClockAccountData),
}

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    Some(match effect {
        Effect::Advance(data) => {
            let previous = ClockAccountData::from_bytes(pre_data);
            assert_eq!(
                previous.block_id.checked_add(1),
                Some(data.block_id),
                "Clock block id must advance by exactly one from the account's own"
            );
            data.to_bytes()
        }
        Effect::Record(data) => data.to_bytes(),
    })
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let Ok([pre_01, pre_10, pre_50]) = <&[_; 3]>::try_from(input.accounts.as_slice()) else {
        panic!("Invalid number of input accounts");
    };

    // Verify the accounts correspond to the expected clock account IDs.
    if pre_01.account_id != CLOCK_01_PROGRAM_ACCOUNT_ID
        || pre_10.account_id != CLOCK_10_PROGRAM_ACCOUNT_ID
        || pre_50.account_id != CLOCK_50_PROGRAM_ACCOUNT_ID
    {
        panic!("Invalid input accounts");
    }

    let Instruction {
        timestamp,
        block_id,
    } = instruction;
    let updated_data = ClockAccountData {
        block_id,
        timestamp,
    };

    let mut plan = Plan::new(input);
    // The schedule below is decided from the proposed block ID, which the transaction is only
    // accepted with if `Advance` finds it one past the every-block account's own.
    plan.effect(pre_01, &Effect::Advance(updated_data));
    if block_id.is_multiple_of(10) {
        plan.effect(pre_10, &Effect::Record(updated_data));
    }
    if block_id.is_multiple_of(50) {
        plan.effect(pre_50, &Effect::Record(updated_data));
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(block_id: u64) -> ClockAccountData {
        ClockAccountData {
            block_id,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn the_every_block_account_advances_by_one() {
        assert_eq!(
            apply(Effect::Advance(data(8)), &data(7).to_bytes()),
            Some(data(8).to_bytes())
        );
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_skips_ahead_is_refused() {
        // The block ID drives the 10/50 schedule, so a forged one would off schedule.
        apply(Effect::Advance(data(9)), &data(7).to_bytes());
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_repeats_is_refused() {
        apply(Effect::Advance(data(7)), &data(7).to_bytes());
    }

    #[test]
    fn a_coarser_account_stores_the_same_values() {
        assert_eq!(
            apply(Effect::Record(data(50)), &data(40).to_bytes()),
            Some(data(50).to_bytes())
        );
    }
}
