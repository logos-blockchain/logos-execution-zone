//! Clock-gated cooldown program.
//!
//! Refuses to run until a configurable cooldown has elapsed since its last
//! successful run, then records the current timestamp.
//!
//! Expected pre-states (in order):
//!   0 - state account (owned by this program)
//!   1 - clock account `CLOCK_01`.
//!
//! State account data layout (16 bytes):
//!   [`cooldown_ms`: u64 LE | `last_run_timestamp`: u64 LE].

use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

struct CooldownState {
    cooldown_ms: u64,
    last_run_timestamp: u64,
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
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([state, clock_pre]) = <[_; 2]>::try_from(pre_states) else {
        panic!("Expected exactly 2 input accounts: state, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

    let clock_data = ClockAccountData::from_bytes(&clock_pre.account.data);
    let current_timestamp = clock_data.timestamp;

    let cooldown_state = CooldownState::from_bytes(&state.account.data);

    // Enforce cooldown: the elapsed time since the last run must exceed the cooldown period.
    let elapsed = current_timestamp.saturating_sub(cooldown_state.last_run_timestamp);
    assert!(
        elapsed >= cooldown_state.cooldown_ms,
        "Cooldown not elapsed: {elapsed}ms since last run, need {}ms",
        cooldown_state.cooldown_ms,
    );

    // Record the run timestamp.
    let updated_state = CooldownState {
        last_run_timestamp: current_timestamp,
        ..cooldown_state
    };
    let mut state_post = state.account.clone();
    state_post.data = updated_state
        .to_bytes()
        .try_into()
        .expect("Cooldown state should fit in account data");

    // Clock account is read-only.
    let clock_post = clock_pre.account.clone();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![state, clock_pre],
        vec![
            AccountPostState::new(state_post),
            AccountPostState::new(clock_post),
        ],
    )
    .write();
}
