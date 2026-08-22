//! Clock Program.
//!
//! A system program that records the current block ID and timestamp into dedicated clock accounts.
//! Three accounts are maintained, updated at different block intervals (every 1, 10, and 50
//! blocks), allowing programs to read recent timestamps at various granularities.
//!
//! This program can only be invoked exclusively by the sequencer as the last transaction in every
//! block. Clock accounts are assigned to the clock program at genesis, so no claiming is required
//! here.

use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData, Instruction,
};
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
};

fn update_if_multiple(
    pre: &AccountWithMetadata,
    divisor: u64,
    current_block_id: u64,
    updated_data: &Data,
) -> AccountDiffOutput {
    let diff_data = current_block_id
        .is_multiple_of(divisor)
        .then(|| updated_data.clone());
    AccountDiffOutput::new(AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data,
    })
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: timestamp,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone());
            write_update_from_diff_output(pre_state, diff_data, data);
            return;
        }
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

    // Verify all clock accounts are owned by this program (assigned at genesis).
    let self_account_id: lee_core::account::AccountId = self_program_id.into();
    if pre_01.account.program_owner != self_account_id
        || pre_10.account.program_owner != self_account_id
        || pre_50.account.program_owner != self_account_id
    {
        panic!("Clock accounts must be owned by the clock program");
    }

    let prev_data = ClockAccountData::from_bytes(&pre_01.account.data);
    let current_block_id = prev_data
        .block_id
        .checked_add(1)
        .expect("Next block id should be within u64 boundaries");

    let updated_data: Data = ClockAccountData {
        block_id: current_block_id,
        timestamp,
    }
    .to_bytes()
    .try_into()
    .expect("clock account data always fits under DATA_MAX_LENGTH");

    let post_01 = update_if_multiple(&pre_01, 1, current_block_id, &updated_data);
    let post_10 = update_if_multiple(&pre_10, 10, current_block_id, &updated_data);
    let post_50 = update_if_multiple(&pre_50, 50, current_block_id, &updated_data);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre_01, pre_10, pre_50],
        vec![post_01, post_10, post_50],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, diff_data: Data) -> Data {
    diff_data
}
