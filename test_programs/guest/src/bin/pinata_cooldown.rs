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
use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, read_lee_call},
};

type Instruction = ();

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
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();

    let [pinata, winner, clock_pre] = input.pre_states.as_slice() else {
        panic!("Expected exactly 3 input accounts: pinata, winner, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);

    let clock_data = ClockAccountData::from_bytes(&clock_pre.account.data);
    let current_timestamp = clock_data.timestamp;

    let pinata_state = PinataState::from_bytes(&pinata.account.data);

    // Enforce cooldown: the elapsed time since the last claim must exceed the cooldown period.
    let elapsed = current_timestamp.saturating_sub(pinata_state.last_claim_timestamp);
    assert!(
        elapsed >= pinata_state.cooldown_ms,
        "Cooldown not elapsed: {elapsed}ms since last claim, need {}ms",
        pinata_state.cooldown_ms,
    );

    // Update the last claim timestamp.
    let updated_state = PinataState {
        last_claim_timestamp: current_timestamp,
        ..pinata_state
    };

    // Capture the fields we still need before the accounts are moved into the final output.
    let pinata_owner = pinata.account.program_owner;

    let pinata_diff = AccountDiff {
        id: pinata.account_id,
        diff_balance: BalanceDiff::Sub(updated_state.prize),
        diff_data: Some(
            updated_state
                .to_bytes()
                .try_into()
                .expect("Pinata state should fit in account data"),
        ),
    };

    let winner_diff = AccountDiff {
        id: winner.account_id,
        diff_balance: BalanceDiff::Add(updated_state.prize),
        diff_data: None,
    };

    // Clock account is read-only.
    let clock_diff = AccountDiff::unchanged(clock_pre.account_id);

    input
        .into_output(vec![
            AccountDiffOutput::new_claimed_if_default(pinata_diff, pinata_owner, Claim::Authorized),
            AccountDiffOutput::new(winner_diff),
            AccountDiffOutput::new(clock_diff),
        ])
        .write();
}
