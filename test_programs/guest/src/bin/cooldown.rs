//! Clock-gated cooldown program.
//!
//! Refuses to run until a configurable cooldown has elapsed since its last successful run, then
//! records the current timestamp. The actor is the state account under this program.
//!
//! State account data layout (16 bytes):
//!   [`cooldown_ms`: u64 LE | `last_run_timestamp`: u64 LE].

use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use lee_core::{
    Timestamp,
    account::Actor,
    program::{ReceiveInput, Response, run_actor},
};

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
    run_actor(receive)
}

fn receive(input: &ReceiveInput, proposed: Timestamp) -> Response {
    let state = CooldownState::from_bytes(&input.pre_state);
    let elapsed = proposed.saturating_sub(state.last_run_timestamp);
    assert!(
        elapsed >= state.cooldown_ms,
        "Cooldown not elapsed: {elapsed}ms since last run, need {}ms",
        state.cooldown_ms,
    );

    Response::write(
        CooldownState {
            last_run_timestamp: proposed,
            ..state
        }
        .to_bytes(),
    )
    .call(
        Actor::new(CLOCK_01_PROGRAM_ACCOUNT_ID, clock_core::clock_account_id()),
        &clock_core::Message::AssertTimestamp {
            at_least: proposed,
            at_most: proposed,
        },
    )
}
