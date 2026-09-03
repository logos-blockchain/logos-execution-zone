use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};

const PING_RECORD_SEED: [u8; 32] = *b"/LEZ/v0.3/PingRecord/0000000000/";
const SENDER_CONFIG_SEED: [u8; 32] = *b"/LEZ/v0.3/PingSenderCfg/0000000/";
const RECEIVER_CONFIG_SEED: [u8; 32] = *b"/LEZ/v0.3/PingReceiverCfg/00000/";
/// Raw 32-byte zone (channel) id, matching the inbox's.
pub type ZoneId = [u8; 32];

/// Instruction to `ping_receiver`.
///
/// Variants are append-only, for the same reason `SenderInstruction`'s are.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ReceiverInstruction {
    /// Record the payload, delivered by the inbox on behalf of a peer source
    /// this receiver authorizes.
    ///
    /// Required accounts (3): the source marker, the receiver config PDA, then
    /// the record PDA.
    Record { payload: Vec<u8> },
    /// Pins the deliverer and the peer sources it may deliver from, written once
    /// into a default config PDA at genesis. A re-run holding anything different
    /// is refused; an identical one is a no-op, which is what genesis replay does.
    ///
    /// Required accounts (1): the receiver config PDA.
    InitConfig(ReceiverConfig),
    /// Replaces the authorized sources. Refused unless the config names an
    /// authority and that account authorized the transaction.
    ///
    /// Required accounts (2): the config PDA, then the authority account.
    UpdateSources { sources: Vec<(ZoneId, ProgramId)> },
    /// Gives up the authority, leaving the source list fixed for good. Refused
    /// unless the config names an authority and that account authorized it.
    ///
    /// Renounce only, never reassign. A leaked key that could rotate would move
    /// the authority to the attacker and lock the real holder out permanently;
    /// with only this, the worst either party achieves is freezing the list,
    /// which is what a config with no authority does anyway.
    ///
    /// Required accounts (2): the config PDA, then the authority account.
    RenounceAuthority,
}

/// Who may deliver to this receiver, and which peer sources they may deliver from.
///
/// `ping_receiver` holds nothing worth stealing, so this is not about value. It is
/// about the record meaning something: without it any program on any configured
/// peer can overwrite the record, and a delivery proves only that some peer sent
/// it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiverConfig {
    /// The program allowed to call `Record`: the cross-zone inbox.
    pub deliverer: ProgramId,
    /// The program allowed to reach the authority instructions through a chained
    /// call, or `None` for top-level only. See `WrappedTokenConfig::governance`.
    pub governance: Option<ProgramId>,
    /// The account allowed to change `sources`, or `None` for a list fixed at
    /// genesis. Seeded unset; see `WrappedTokenConfig::authority` for why.
    pub authority: Option<AccountId>,
    /// The `(src_zone, src_program_id)` pairs a delivery may originate from.
    pub sources: Vec<(ZoneId, ProgramId)>,
}

impl ReceiverConfig {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("receiver config serializes")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// Instruction to `ping_sender`. `Send`'s emission fields are forwarded verbatim
/// into `cross_zone_outbox::Instruction::Emit`.
///
/// Variants are append-only. Borsh encodes the variant as a leading tag byte,
/// so inserting one ahead of `Send` shifts every existing encoding.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SenderInstruction {
    /// Emit a cross-zone message through the pinned outbox.
    ///
    /// Required accounts (2): the sender config PDA, then the outbox PDA.
    Send {
        target_zone: [u8; 32],
        target_program_id: ProgramId,
        target_accounts: Vec<[u8; 32]>,
        payload: Vec<u8>,
        ordinal: u32,
    },
    /// Pins the outbox program, written once into a default config PDA at
    /// genesis. A re-run naming a different outbox is refused; an identical one
    /// is a no-op, which is what genesis replay does.
    ///
    /// Required accounts (1): the sender config PDA.
    InitConfig { outbox_program_id: ProgramId },
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

/// PDA holding the outbox program id, seeded at genesis so the guest can pin the
/// program it chains into without importing the outbox image id.
#[must_use]
pub fn sender_config_account_id(sender_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&sender_id, &sender_config_seed())
}

#[must_use]
pub const fn sender_config_seed() -> PdaSeed {
    PdaSeed::new(SENDER_CONFIG_SEED)
}

/// PDA holding the sources `ping_receiver` accepts a delivery from.
#[must_use]
pub fn receiver_config_account_id(receiver_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&receiver_id, &receiver_config_seed())
}

#[must_use]
pub const fn receiver_config_seed() -> PdaSeed {
    PdaSeed::new(RECEIVER_CONFIG_SEED)
}

/// Encodes the pinned outbox program id for the config account's data.
#[must_use]
pub fn outbox_bytes(outbox_program_id: ProgramId) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (word, chunk) in outbox_program_id.iter().zip(bytes.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Decodes the pinned outbox program id from the config account's data.
#[must_use]
pub fn read_outbox(data: &[u8]) -> Option<ProgramId> {
    if data.len() < 32 {
        return None;
    }
    let mut outbox_program_id = [0_u32; 8];
    for (word, chunk) in outbox_program_id.iter_mut().zip(data[..32].chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap_or_else(|_| unreachable!()));
    }
    Some(outbox_program_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `extract_emission` decodes `Send` off peer transactions, so its tag byte is
    /// wire format: a variant inserted ahead of it would silently shift every
    /// existing encoding.
    #[test]
    fn send_is_the_first_variant() {
        let send = SenderInstruction::Send {
            target_zone: [7; 32],
            target_program_id: [1; 8],
            target_accounts: vec![],
            payload: vec![],
            ordinal: 0,
        };
        let bytes = borsh::to_vec(&send).expect("Send serializes");
        assert_eq!(bytes[0], 0);
    }

    /// `Record` is serialized by the source zone into the emission payload and
    /// decoded by the destination, so its tag byte is wire format.
    #[test]
    fn record_is_the_first_variant() {
        let record = ReceiverInstruction::Record { payload: vec![] };
        let bytes = borsh::to_vec(&record).expect("Record serializes");
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn an_empty_receiver_config_does_not_decode() {
        assert_eq!(ReceiverConfig::from_bytes(&[]), None);
    }

    #[test]
    fn receiver_config_round_trips() {
        let config = ReceiverConfig {
            deliverer: [1; 8],
            governance: None,
            authority: None,
            sources: vec![([7; 32], [9; 8])],
        };
        assert_eq!(ReceiverConfig::from_bytes(&config.to_bytes()), Some(config));
    }

    #[test]
    fn outbox_id_round_trips() {
        let outbox: ProgramId = [9; 8];
        assert_eq!(read_outbox(&outbox_bytes(outbox)), Some(outbox));
    }
}
