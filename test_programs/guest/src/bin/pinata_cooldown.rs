//! Cooldown-based pinata program.
//!
//! A Piñata program that uses the on-chain clock to prevent abuse.
//! After each prize claim the program records the current timestamp; the next claim is only
//! allowed once a configurable cooldown period has elapsed.
//!
//! Pinata account data layout (24 bytes):
//!   [prize: u64 LE | `cooldown_ms`: u64 LE | `last_claim_timestamp`: u64 LE].

use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, PdaSeed, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

const PRIZE_SEED: PdaSeed = PdaSeed::new([0; 32]);

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
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pinata, prize_pda, winner, clock_pre]) = <[_; 4]>::try_from(pre_states) else {
        panic!("Expected exactly 4 input accounts: pinata, prize_pda, winner, clock");
    };

    // Check the clock account is the system clock account
    assert_eq!(clock_pre.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);
    assert_eq!(
        prize_pda.account_id,
        AccountId::for_public_pda(&self_program_id, &PRIZE_SEED),
        "Second account must be the prize-pool PDA"
    );

    let clock_data = ClockAccountData::from_bytes(&clock_pre.account.data.clone().into_inner());
    let current_timestamp = clock_data.timestamp;

    let pinata_state = PinataState::from_bytes(&pinata.account.data.clone().into_inner());

    // Enforce cooldown: the elapsed time since the last claim must exceed the cooldown period.
    let elapsed = current_timestamp.saturating_sub(pinata_state.last_claim_timestamp);
    assert!(
        elapsed >= pinata_state.cooldown_ms,
        "Cooldown not elapsed: {elapsed}ms since last claim, need {}ms",
        pinata_state.cooldown_ms,
    );

    let mut pinata_post = pinata.account.clone();
    let prize_pda_post = prize_pda.account.clone();
    let winner_post = winner.account.clone();
    let clock_post = clock_pre.account.clone();

    let mut prize_authorized = prize_pda.clone();
    prize_authorized.is_authorized = true;

    let chained_call = ChainedCall::new(
        prize_authorized.account.program_owner.into(),
        vec![prize_authorized, winner.clone()],
        &authenticated_transfer_core::Instruction::Transfer {
            amount: pinata_state.prize,
        },
    )
    .with_pda_seeds(vec![PRIZE_SEED]);

    // Update the last claim timestamp.
    let updated_state = PinataState {
        last_claim_timestamp: current_timestamp,
        ..pinata_state
    };
    pinata_post.data = updated_state
        .to_bytes()
        .try_into()
        .expect("Pinata state should fit in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pinata, prize_pda, winner, clock_pre],
        vec![
            AccountPostState::new(pinata_post),
            AccountPostState::new(prize_pda_post),
            AccountPostState::new(winner_post),
            AccountPostState::new(clock_post),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
