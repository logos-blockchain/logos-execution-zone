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
use nssa_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs};

/// (`amount`, `deadline_timestamp`).
type Instruction = (u128, u64);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            pre_states,
            instruction: (amount, deadline),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([sender_pre, receiver_pre, clock_pre]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Expected exactly 3 input accounts: sender, receiver, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

    // Read the current timestamp from the clock account.
    let clock_data = ClockAccountData::from_bytes(&clock_pre.account.data.clone().into_inner());

    assert!(
        clock_data.timestamp >= deadline,
        "Transfer is time-locked until timestamp {deadline}, current is {}",
        clock_data.timestamp,
    );

    let mut sender_post = sender_pre.account.clone();
    let mut receiver_post = receiver_pre.account.clone();

    sender_post.balance = sender_post
        .balance
        .checked_sub(amount)
        .expect("Insufficient balance");
    receiver_post.balance = receiver_post
        .balance
        .checked_add(amount)
        .expect("Balance overflow");

    // Clock account is read-only: post state equals pre state.
    let clock_post = clock_pre.account.clone();

    ProgramOutput::new(
        self_program_id,
        instruction_words,
        vec![sender_pre, receiver_pre, clock_pre],
        vec![
            AccountPostState::new(sender_post),
            AccountPostState::new(receiver_post),
            AccountPostState::new(clock_post),
        ],
    )
    .write();
}
