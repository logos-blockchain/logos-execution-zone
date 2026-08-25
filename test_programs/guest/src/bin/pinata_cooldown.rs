//! Cooldown-based pinata program.
//!
//! A Piñata program that uses the on-chain clock to prevent abuse.
//! After each prize claim the program records the current timestamp; the next claim is only
//! allowed once a configurable cooldown period has elapsed.
//!
//! Expected pre-states (in order):
//!   0 - pinata account (authorized, owned by this program)
//!   1 - winner account
//!   2 - clock account `CLOCK_01`.
//!
//! Pinata account data layout (24 bytes):
//!   [prize: u64 LE | `cooldown_ms`: u64 LE | `last_claim_timestamp`: u64 LE].

use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

/// `(clock_program_id, native_program)` — the slot holding the clock's data and the
/// slot credited at the winner.
type Instruction = (lee_core::program::ProgramId, lee_core::program::ProgramId);

struct PinataState {
    prize: u128,
    cooldown_ms: u64,
    last_claim_timestamp: u64,
}

impl PinataState {
    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 32, "Pinata account data too short");
        let prize = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let cooldown_ms = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let last_claim_timestamp = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        Self {
            prize,
            cooldown_ms,
            last_claim_timestamp,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.prize.to_le_bytes());
        buf.extend_from_slice(&self.cooldown_ms.to_le_bytes());
        buf.extend_from_slice(&self.last_claim_timestamp.to_le_bytes());
        buf
    }
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (clock_program_id, native_program),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pinata, winner, clock_pre]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Expected exactly 3 input accounts: pinata, winner, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

    let clock_data = ClockAccountData::from_bytes(clock_pre.account.data(clock_program_id));
    let current_timestamp = clock_data.timestamp;

    let pinata_state = PinataState::from_bytes(pinata.account.data(self_program_id));

    // Enforce cooldown: the elapsed time since the last claim must exceed the cooldown period.
    let elapsed = current_timestamp.saturating_sub(pinata_state.last_claim_timestamp);
    assert!(
        elapsed >= pinata_state.cooldown_ms,
        "Cooldown not elapsed: {elapsed}ms since last claim, need {}ms",
        pinata_state.cooldown_ms,
    );

    let mut pinata_post = pinata.account.clone();
    let mut winner_post = winner.account.clone();

    let pinata_slot = pinata_post.slot_mut(self_program_id);
    pinata_slot.balance = pinata_slot
        .balance
        .checked_sub(pinata_state.prize)
        .expect("Not enough balance in the pinata");

    let winner_slot = winner_post.slot_mut(native_program);
    winner_slot.balance = winner_slot
        .balance
        .checked_add(pinata_state.prize)
        .expect("Overflow when adding prize to winner");
    winner_post.prune();

    // Update the last claim timestamp.
    let updated_state = PinataState {
        last_claim_timestamp: current_timestamp,
        ..pinata_state
    };
    pinata_post.slot_mut(self_program_id).data = updated_state
        .to_bytes()
        .try_into()
        .expect("Pinata state should fit in account data");
    pinata_post.prune();

    // Clock account is read-only.
    let clock_post = clock_pre.account.clone();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pinata, winner, clock_pre],
        vec![
            pinata_post,
            winner_post,
            clock_post,
        ],
    )
    .write();
}
