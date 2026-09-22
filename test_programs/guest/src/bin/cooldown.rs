//! Clock-gated cooldown program.
//!
//! Refuses to run until a configurable cooldown has elapsed since its last successful run, then
//! records the current timestamp. The instruction carries the caller's proposal for what the
//! clock reads; the guard on the clock account is what pins it before the cooldown is measured
//! from it.
//!
//! Expected accounts (in order):
//!   0 - state account (owned by this program)
//!   1 - clock account `CLOCK_01`.
//!
//! State account data layout (16 bytes):
//!   [`cooldown_ms`: u64 LE | `last_run_timestamp`: u64 LE].

use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::{
    Timestamp,
    program::{LeeCall, Plan, Proposed, read_lee_call, resolve_keep, resolve_write},
};

type Instruction = Timestamp;

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// The run timestamp is instruction-supplied and untrusted. Promoting it to `Checked` emits
    /// this guard, which is the only way to obtain the value `Run` records.
    TimestampIs(Timestamp),
    Run(Timestamp),
}

struct CooldownState {
    cooldown_ms: u64,
    last_run_timestamp: Timestamp,
}

impl CooldownState {
    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 16, "State account data too short");
        let cooldown_ms = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let last_run_timestamp = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Self {
            cooldown_ms,
            last_run_timestamp,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&self.cooldown_ms.to_le_bytes());
        buf.extend_from_slice(&self.last_run_timestamp.to_le_bytes());
        buf
    }
}

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let Ok([state, clock]) = <[_; 2]>::try_from(input.accounts.clone()) else {
                panic!("Expected exactly 2 input accounts: state, clock");
            };
            assert_eq!(clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

            let proposed = input.instruction;
            let mut plan = Plan::new(&input, instruction_data);
            let now = plan.require(
                &clock,
                &Effect::TimestampIs(proposed),
                Proposed::new(proposed),
            );
            plan.update(&state, &Effect::Run(now.get()));
            plan.write()
        }
        LeeCall::Resolve(input) => {
            match borsh::from_slice(&input.effect_data).expect("cooldown wrote its own effect") {
                Effect::TimestampIs(proposed) => {
                    let clock = ClockAccountData::from_bytes(&input.pre_data);
                    assert_eq!(
                        clock.timestamp, proposed,
                        "Proposed timestamp {proposed} is not the clock's timestamp {}",
                        clock.timestamp,
                    );
                    resolve_keep(input)
                }
                Effect::Run(now) => {
                    let state = CooldownState::from_bytes(&input.pre_data);
                    let elapsed = now.saturating_sub(state.last_run_timestamp);
                    assert!(
                        elapsed >= state.cooldown_ms,
                        "Cooldown not elapsed: {elapsed}ms since last run, need {}ms",
                        state.cooldown_ms,
                    );
                    resolve_write(
                        input,
                        CooldownState {
                            last_run_timestamp: now,
                            ..state
                        }
                        .to_bytes()
                        .try_into()
                        .expect("Cooldown state should fit in account data"),
                    )
                }
            }
        }
    }
}
