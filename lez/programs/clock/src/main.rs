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
use lee_core::program::{LeeCall, Plan, ProgramInput, Proposed, read_lee_call, resolve_write};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// Advancing by exactly one is what pins the proposed block ID the 10- and 50-block
    /// schedule is decided from.
    Advance(ClockAccountData),
    Record(ClockAccountData),
}

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => execute(input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect =
                borsh::from_slice(&input.effect_data).expect("the clock wrote its own effect");
            let data = resolve_effect(&effect, &input.pre_data)
                .try_into()
                .expect("Clock account data should fit in account data");
            resolve_write(input, data)
        }
    }
}

fn resolve_effect(effect: &Effect, pre_data: &[u8]) -> Vec<u8> {
    match effect {
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
    }
}

fn execute(input: ProgramInput<Instruction>, instruction_data: Vec<u8>) -> ! {
    let Ok([pre_01, pre_10, pre_50]) = <[_; 3]>::try_from(input.accounts.clone()) else {
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
    } = input.instruction;
    let updated_data = ClockAccountData {
        block_id,
        timestamp,
    };

    let mut plan = Plan::new(&input, instruction_data);
    // The every-block account resolves first: the schedule below may only be decided from a
    // block ID its own account has already vouched for.
    let current_block_id = plan.require(
        &pre_01,
        &Effect::Advance(updated_data),
        Proposed::new(block_id),
    );
    if current_block_id.get().is_multiple_of(10) {
        plan.update(&pre_10, &Effect::Record(updated_data));
    }
    if current_block_id.get().is_multiple_of(50) {
        plan.update(&pre_50, &Effect::Record(updated_data));
    }
    plan.write()
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
            resolve_effect(&Effect::Advance(data(8)), &data(7).to_bytes()),
            data(8).to_bytes()
        );
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_skips_ahead_is_refused() {
        // The block ID drives the 10/50 schedule, so a forged one would silently move every
        // coarser clock account off its cadence.
        resolve_effect(&Effect::Advance(data(9)), &data(7).to_bytes());
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_repeats_is_refused() {
        resolve_effect(&Effect::Advance(data(7)), &data(7).to_bytes());
    }

    #[test]
    fn a_coarser_account_stores_the_same_values() {
        assert_eq!(
            resolve_effect(&Effect::Record(data(50)), &data(40).to_bytes()),
            data(50).to_bytes()
        );
    }
}
