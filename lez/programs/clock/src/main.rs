//! Clock Program.
//!
//! A system program that records the current block ID and timestamp into dedicated clock accounts.
//! Three accounts are maintained, updated at different block intervals (every 1, 10, and 50
//! blocks), allowing programs to read recent timestamps at various granularities.
//!
//! This program can only be invoked exclusively by the sequencer as the last transaction in every
//! block. Clock accounts are seeded at genesis.

use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData, Instruction,
};
use lee_core::{
    account::{Input, Slot},
    program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

fn update_if_multiple(
    pre: &Input,
    self_program_id: ProgramId,
    divisor: u64,
    current_block_id: u64,
    updated_data: &[u8],
) -> Slot {
    let mut post = pre.slot_of(self_program_id).clone();
    if current_block_id.is_multiple_of(divisor) {
        post.data = updated_data
            .to_vec()
            .try_into()
            .expect("Clock account data should fit in account data");
    }
    post
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: timestamp,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

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

    let prev_data = ClockAccountData::from_bytes(pre_01.data(self_program_id));
    let current_block_id = prev_data
        .block_id
        .checked_add(1)
        .expect("Next block id should be within u64 boundaries");

    let updated_data = ClockAccountData {
        block_id: current_block_id,
        timestamp,
    }
    .to_bytes();

    let post_01 = update_if_multiple(&pre_01, self_program_id, 1, current_block_id, &updated_data);
    let post_10 = update_if_multiple(
        &pre_10,
        self_program_id,
        10,
        current_block_id,
        &updated_data,
    );
    let post_50 = update_if_multiple(
        &pre_50,
        self_program_id,
        50,
        current_block_id,
        &updated_data,
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre_01, pre_10, pre_50],
        vec![Some(post_01), Some(post_10), Some(post_50)],
    )
    .write();
}
