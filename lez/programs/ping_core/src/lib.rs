use borsh::{BorshDeserialize, BorshSerialize};
pub use cross_zone_receiver_core::{
    ReceiverConfig, receiver_config_account_id, receiver_config_seed,
};
pub use lee_core::account::ZoneId;
use lee_core::{
    account::{AccountId, Actor},
    program::PdaSeed,
};

const PING_RECORD_SEED: [u8; 32] = *b"/LEZ/v0.3/PingRecord/0000000000/";

pub const PING_SENDER_NAME: lee_core::program::SystemProgramName =
    lee_core::program::SystemProgramName::new(b"ping_sender");
pub const PING_RECEIVER_NAME: lee_core::program::SystemProgramName =
    lee_core::program::SystemProgramName::new(b"ping_receiver");

/// Message to `ping_receiver`.
///
/// Variants are append-only, for the same reason `SenderMessage`'s are.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ReceiverMessage {
    /// Record the payload, delivered by the inbox on behalf of a peer source
    /// this receiver authorizes.
    ///
    /// Only ever the payload of a delivery to the receiver's program account.
    Record {
        payload: Vec<u8>,
    },
    /// Pins the deliverer and the peer sources it may deliver from, written once
    /// into an empty config actor state at genesis. A re-run holding anything different
    /// is refused; an identical one is a no-op, which is what genesis replay does.
    ///
    /// Sent to the receiver config PDA.
    InitConfig(ReceiverConfig),
    /// Replaces the authorized sources. Refused unless the config names an
    /// authority and that account authorized the transaction.
    ///
    /// Sent to the authority's own actor under this program, which forwards it to
    /// the config PDA naming itself as `authority` and the program that sent it,
    /// if any, as `via`.
    UpdateSources {
        authority: AccountId,
        via: Option<AccountId>,
        sources: Vec<(ZoneId, AccountId)>,
    },
    /// Gives up the authority, leaving the source list fixed for good. Refused
    /// unless the config names an authority and that account authorized it.
    ///
    /// Renounce only, never reassign. A leaked key that could rotate would move
    /// the authority to the attacker and lock the real holder out permanently;
    /// with only this, the worst either party achieves is freezing the list,
    /// which is what a config with no authority does anyway.
    ///
    /// Sent like `UpdateSources`.
    RenounceAuthority {
        authority: AccountId,
        via: Option<AccountId>,
    },
    RecordFrom {
        deliverer: AccountId,
        src_zone: ZoneId,
        src_account_id: AccountId,
        payload: Vec<u8>,
    },
    WriteRecord(Vec<u8>),
}

/// Message to `ping_sender`'s own program actor.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SenderMessage {
    /// Send `payload` to `target` in `target_zone`, declaring `accounts` for its
    /// delivery. Callers name any target, which is why routes pin the pair.
    Send {
        target_zone: ZoneId,
        target: Actor,
        accounts: Vec<Actor>,
        payload: Vec<u8>,
    },
}

#[must_use]
pub fn ping_sender_account_id() -> AccountId {
    AccountId::from_system_program_name(&PING_SENDER_NAME)
}

#[must_use]
pub fn ping_receiver_account_id() -> AccountId {
    AccountId::from_system_program_name(&PING_RECEIVER_NAME)
}

/// The account a `ping_receiver` records the latest delivered payload into.
#[must_use]
pub fn ping_record_pda(receiver_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&receiver_id, &ping_record_seed())
}

/// Seed of the record PDA.
#[must_use]
pub const fn ping_record_seed() -> PdaSeed {
    PdaSeed::new(PING_RECORD_SEED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Record` is serialized by the source zone into the emission payload and
    /// decoded by the destination, so its tag byte is wire format.
    #[test]
    fn record_is_the_first_variant() {
        let record = ReceiverMessage::Record { payload: vec![] };
        let bytes = borsh::to_vec(&record).expect("Record serializes");
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn an_empty_receiver_config_does_not_decode() {
        assert_eq!(ReceiverConfig::from_bytes(&[]), None);
    }

    /// `ping_receiver` is the reference receiver, so its `InitConfig` encoding
    /// must be exactly the shared contract's: the tag, then the config.
    #[test]
    fn init_config_matches_the_receiver_contract_encoding() {
        let config = ReceiverConfig {
            deliverer: AccountId::new([1; 32]),
            governance: None,
            authority: None,
            sources: vec![([7; 32], AccountId::new([9; 32]))],
        };
        assert_eq!(
            borsh::to_vec(&ReceiverMessage::InitConfig(config.clone()))
                .expect("InitConfig serializes"),
            cross_zone_receiver_core::init_config_instruction_bytes(&config)
        );
    }

    #[test]
    fn receiver_config_round_trips() {
        let config = ReceiverConfig {
            deliverer: AccountId::new([1; 32]),
            governance: None,
            authority: None,
            sources: vec![([7; 32], AccountId::new([9; 32]))],
        };
        assert_eq!(ReceiverConfig::from_bytes(&config.to_bytes()), Some(config));
    }
}
