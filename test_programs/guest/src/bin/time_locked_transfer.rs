//! Time-locked transfer program.
//!
//! Demonstrates how a program can include a clock account among its inputs and use the on-chain
//! timestamp in its logic. The transfer only executes when the clock timestamp is at or past a
//! caller-supplied deadline; otherwise the program panics.
//!
//! Expected pre-states (in order):
//!   0 - sender account (authorized)
//!   1 - receiver account
//!   2 - clock account (read-only, e.g. `CLOCK_01`).

use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

/// (`amount`, `deadline_timestamp`).
type Instruction = (u128, u64);

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (amount, deadline),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([sender_pre, receiver_pre, clock_pre]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Expected exactly 3 input accounts: sender, receiver, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

    // Read the current timestamp from the clock account.
    let clock_data = ClockAccountData::from_bytes(&clock_pre.account.data);

    assert!(
        clock_data.timestamp >= deadline,
        "Transfer is time-locked until timestamp {deadline}, current is {}",
        clock_data.timestamp,
    );

    let sender_diff = AccountDiff {
        id: sender_pre.account_id,
        diff_balance: BalanceDiff::Sub(amount),
        diff_data: None,
    };
    let receiver_diff = AccountDiff {
        id: receiver_pre.account_id,
        diff_balance: BalanceDiff::Add(amount),
        diff_data: None,
    };

    // Clock account is read-only: post state equals pre state.
    let clock_diff = AccountDiff::unchanged(clock_pre.account_id);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![sender_pre, receiver_pre, clock_pre],
        vec![
            AccountDiffOutput::new(sender_diff),
            AccountDiffOutput::new(receiver_diff),
            AccountDiffOutput::new(clock_diff),
        ],
    )
    .write();
}
