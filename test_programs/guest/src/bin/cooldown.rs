//! Clock-gated cooldown program.
//!
//! Reads the clock's timestamp, refuses to run until a configurable cooldown has elapsed since its
//! last successful run, then records the timestamp. The actor is the state account under this
//! program.
//!
//! State account data layout (16 bytes):
//!   [`cooldown_ms`: u64 LE | `last_run_timestamp`: u64 LE].

use clock_core::Reply;
use lee_core::{
    Timestamp,
    program::{ReceiveInput, Response},
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

lee_core::actor_entrypoint!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    let clock = clock_core::clock_actor();
    if input.from != Some(clock.into()) {
        return Response::keep_state().send_sync(
            clock,
            &clock_core::Message::ReadTimestamp { granularity: 1 },
        );
    }
    let Reply::Timestamp(now) = Reply::from_message(&input.message) else {
        panic!("Cooldown reads only the clock's timestamp");
    };
    let state = CooldownState::from_bytes(&input.pre_state);
    let elapsed = now.saturating_sub(state.last_run_timestamp);
    assert!(
        elapsed >= state.cooldown_ms,
        "Cooldown not elapsed: {elapsed}ms since last run, need {}ms",
        state.cooldown_ms,
    );

    Response::set_state(
        CooldownState {
            last_run_timestamp: now,
            ..state
        }
        .to_bytes(),
    )
}
