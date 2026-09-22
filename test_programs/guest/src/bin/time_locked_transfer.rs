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
    program::{ChainedCall, LeeCall, Plan, read_lee_call, resolve_keep},
};

/// (`amount`, `deadline_timestamp`).
type Instruction = (u128, Timestamp);

/// It never writes: the clock shard belongs to the clock program, so the only sound outcome of
/// a foreign inspection is `Keep`.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct DeadlineReached(Timestamp);

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let Ok([sender, receiver, clock]) = <[_; 3]>::try_from(input.accounts.clone()) else {
                panic!("Expected exactly 3 input accounts: sender, receiver, clock");
            };
            assert_eq!(clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

            let (amount, deadline) = input.instruction;
            let mut plan = Plan::new(&input, instruction_data);
            plan.effect(&clock, &DeadlineReached(deadline));
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
        LeeCall::Resolve(input) => {
            let DeadlineReached(deadline) = borsh::from_slice(&input.effect_data)
                .expect("time_locked_transfer wrote its own effect");
            let clock = ClockAccountData::from_bytes(&input.pre_data);
            assert!(
                clock.timestamp >= deadline,
                "Transfer is time-locked until timestamp {deadline}, current is {}",
                clock.timestamp,
            );
            resolve_keep(input)
        }
    }
}
