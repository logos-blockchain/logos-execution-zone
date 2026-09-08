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
use lee_core::{
    account::{AccountInput, BalanceDiff},
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

fn update_if_multiple(
    pre: AccountInput,
    divisor: u64,
    current_block_id: u64,
    updated_data: &[u8],
) -> AccountStateDiff {
    if current_block_id.is_multiple_of(divisor) {
        let new_data = updated_data
            .to_vec()
            .try_into()
            .expect("Clock account data should fit in account data");
        AccountStateDiff::new(pre, BalanceDiff::Add(0), new_data)
    } else {
        AccountStateDiff::unchanged(pre)
    }
}

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: timestamp,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre_01, pre_10, pre_50]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Invalid number of input accounts");
    };

    // Verify pre-states correspond to the expected clock account IDs.
    if pre_01.account_id != CLOCK_01_PROGRAM_ACCOUNT_ID
        || pre_10.account_id != CLOCK_10_PROGRAM_ACCOUNT_ID
        || pre_50.account_id != CLOCK_50_PROGRAM_ACCOUNT_ID
    {
        panic!("Invalid input accounts");
    }

    let prev_data = ClockAccountData::from_bytes(pre_01.shard_of(self_account_id));
    let current_block_id = prev_data
        .block_id
        .checked_add(1)
        .expect("Next block id should be within u64 boundaries");

    let updated_data = ClockAccountData {
        block_id: current_block_id,
        timestamp,
    }
    .to_bytes();

    let diff_01 = update_if_multiple(pre_01, 1, current_block_id, &updated_data);
    let diff_10 = update_if_multiple(pre_10, 10, current_block_id, &updated_data);
    let diff_50 = update_if_multiple(pre_50, 50, current_block_id, &updated_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![diff_01, diff_10, diff_50],
    )
    .write();
}
