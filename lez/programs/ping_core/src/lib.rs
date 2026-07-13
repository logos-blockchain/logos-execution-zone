use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

const PING_RECORD_SEED: [u8; 32] = *b"/LEZ/v0.3/PingRecord/0000000000/";

/// Instruction delivered to `ping_receiver` by the inbox: record the payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiverInstruction {
    Record { payload: Vec<u8> },
}

/// Instruction to `ping_sender`: forwarded verbatim into `cross_zone_outbox::Instruction::Emit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SenderInstruction {
    Send {
        outbox_program_id: ProgramId,
        target_zone: [u8; 32],
        target_program_id: ProgramId,
        target_accounts: Vec<[u8; 32]>,
        payload: Vec<u8>,
        ordinal: u32,
    },
}

/// The account a `ping_receiver` records the latest delivered payload into.
#[must_use]
pub fn ping_record_pda(receiver_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&receiver_id, &ping_record_seed())
}

/// Seed of the record PDA, exposed so the guest can claim the account.
#[must_use]
pub const fn ping_record_seed() -> PdaSeed {
    PdaSeed::new(PING_RECORD_SEED)
}
