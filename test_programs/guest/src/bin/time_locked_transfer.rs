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
use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

/// (`amount`, `deadline_timestamp`).
type Instruction = (u128, u64, lee_core::program::ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (amount, deadline, clock_program_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([sender_pre, receiver_pre, clock_pre]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Expected exactly 3 input accounts: sender, receiver, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

    // Read the current timestamp from the clock account.
    let clock_data = ClockAccountData::from_bytes(clock_pre.account.data(clock_program_id));

    assert!(
        clock_data.timestamp >= deadline,
        "Transfer is time-locked until timestamp {deadline}, current is {}",
        clock_data.timestamp,
    );

    let mut sender_post = sender_pre.account.clone();
    let mut receiver_post = receiver_pre.account.clone();

    let sender_slot = sender_post.slot_mut(self_program_id);
    sender_slot.balance = sender_slot
        .balance
        .checked_sub(amount)
        .expect("Insufficient balance");
    sender_post.prune();

    let receiver_slot = receiver_post.slot_mut(self_program_id);
    receiver_slot.balance = receiver_slot
        .balance
        .checked_add(amount)
        .expect("Balance overflow");
    receiver_post.prune();

    // Clock account is read-only: post state equals pre state.
    let clock_post = clock_pre.account.clone();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![sender_pre, receiver_pre, clock_pre],
        vec![
            sender_post,
            receiver_post,
            clock_post,
        ],
    )
    .write();
}
