//! Time-locked transfer program.
//!
//! Demonstrates how a program gates on the on-chain timestamp without reading it: the deadline
//! travels in the instruction and a guard effect on the clock account is what compares it
//! against the clock's own timestamp. The transfer only settles when the clock is at or past
//! the deadline; otherwise the guard panics and the whole transaction rolls back.
//!
//! Expected accounts (in order):
//!   0 - sender account (authorized)
//!   1 - receiver account
//!   2 - clock account (read-only, e.g. `CLOCK_01`).

use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::{
    Timestamp,
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{ChainedCall, Plan, ProgramCall, apply_keep, read_program_call},
};

/// (`amount`, `deadline_timestamp`).
type Instruction = (u128, Timestamp);

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct DeadlineReached(Timestamp);

fn main() {
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, instruction) => {
            let Ok([sender, receiver, clock]) = <[_; 3]>::try_from(input.accounts.clone()) else {
                panic!("Expected exactly 3 input accounts: sender, receiver, clock");
            };
            assert_eq!(clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

            let (amount, deadline) = instruction;
            let mut plan = Plan::new(&input);
            // Only the clock's own invocation may modify a clock account, so whichever shard the
            // handle names holds the clock's data or nothing.
            plan.inspect(&clock, clock.program_account_id, &DeadlineReached(deadline));
            plan.call(ChainedCall::new(
                NATIVE_TOKEN_PROGRAM_ID,
                vec![
                    ProgramShardSelector::from(&sender),
                    ProgramShardSelector::from(&receiver),
                ],
                &NativeInstruction::Transfer { amount },
            ));
            plan.write()
        }
        ProgramCall::Apply(input) => {
            let DeadlineReached(deadline) = borsh::from_slice(&input.effect_data)
                .expect("time_locked_transfer wrote its own effect");
            let clock = ClockAccountData::from_bytes(&input.pre_data);
            assert!(
                clock.timestamp >= deadline,
                "Transfer is time-locked until timestamp {deadline}, current is {}",
                clock.timestamp,
            );
            apply_keep(input)
        }
    }
}
