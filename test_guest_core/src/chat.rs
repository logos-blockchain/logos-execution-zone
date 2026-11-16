//! Types for the `zone_chat` test guest: a program with no builtin privileges
//! that is both a generic emitter and a conforming receiver.

use borsh::{BorshDeserialize, BorshSerialize};
pub use cross_zone_emission_core::{CrossZoneEmission, EMITTER_MAGIC};
pub use cross_zone_receiver_core::{
    Delivery, INIT_CONFIG_TAG, ReceiverConfig, ZoneId, init_config_instruction_bytes,
    receiver_config_account_id, receiver_config_seed,
};
use lee_core::{account::AccountId, program::PdaSeed};

const CHAT_LOG_SEED: [u8; 32] = *b"/LEZ/test/ZoneChatLog/0000000000";

/// Newest-last entries kept in the log; older ones are dropped.
pub const CHAT_LOG_CAP: usize = 64;

/// `zone_chat`'s instruction set. The first two tags are the two cross-zone
/// contracts: `Post` the emitter shape, `InitConfig` the receiver's claim.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ChatMessage {
    /// Declare an outbound message; the watcher reads the emission off this
    /// instruction when the program is listed in the peer's emitters. `magic`
    /// must be [`EMITTER_MAGIC`]: it is how the variant opts into the contract.
    Post {
        magic: [u8; 8],
        emission: CrossZoneEmission,
    },
    /// Claims the receiver config. At the program actor it requires the
    /// program account's authorization (the deployer's key) and is forwarded
    /// to the config PDA, where the write is once-only. A rewrite must be
    /// identical.
    InitConfig(ReceiverConfig),
    /// The program account forwards a delivery to the config, naming the
    /// program that sent it. Internal.
    DeliverFrom {
        deliverer: AccountId,
        src_zone: ZoneId,
        src_account_id: AccountId,
        payload: Vec<u8>,
    },
    /// The config appends an authorized delivery to the log. Internal.
    WriteLog { src_zone: ZoneId, text: Vec<u8> },
}

impl ChatMessage {
    /// A [`ChatMessage::Post`] carrying the contract's magic, so no caller
    /// hand-writes it.
    #[must_use]
    pub const fn post(emission: CrossZoneEmission) -> Self {
        Self::Post {
            magic: EMITTER_MAGIC,
            emission,
        }
    }
}

/// The per-zone message log, newest last.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChatLog {
    pub entries: Vec<(ZoneId, Vec<u8>)>,
}

impl ChatLog {
    /// Decodes a log from account data; empty data is an empty log.
    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        borsh::from_slice(bytes)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("chat log serializes")
    }

    pub fn push(&mut self, src_zone: ZoneId, text: Vec<u8>) {
        self.entries.push((src_zone, text));
        if self.entries.len() > CHAT_LOG_CAP {
            self.entries.remove(0);
        }
    }
}

/// The account the chat log lives in.
#[must_use]
pub fn chat_log_account_id(chat_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&chat_id, &chat_log_seed())
}

#[must_use]
pub const fn chat_log_seed() -> PdaSeed {
    PdaSeed::new(CHAT_LOG_SEED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Post`'s encoding must be exactly the generic emitter contract, or the
    /// guest this crate exists for would not be recognized.
    #[test]
    fn post_matches_the_generic_emitter_contract() {
        let emission = CrossZoneEmission {
            target_zone: [2; 32],
            target_account_id: AccountId::new([9; 32]),
            target_accounts: vec![],
            payload: b"hi".to_vec(),
            ordinal: 0,
        };
        let bytes = borsh::to_vec(&ChatMessage::Post {
            magic: EMITTER_MAGIC,
            emission: emission.clone(),
        })
        .expect("Post serializes");
        assert_eq!(
            cross_zone_emission_core::declared_emission(&bytes),
            Some(emission)
        );
    }

    /// `InitConfig`'s encoding must be exactly the receiver contract's.
    #[test]
    fn init_config_matches_the_receiver_contract() {
        let config = ReceiverConfig {
            deliverer: AccountId::new([1; 32]),
            governance: None,
            authority: None,
            sources: vec![([7; 32], AccountId::new([9; 32]))],
        };
        assert_eq!(
            borsh::to_vec(&ChatMessage::InitConfig(config.clone())).expect("InitConfig serializes"),
            init_config_instruction_bytes(&config)
        );
    }

    #[test]
    fn the_log_caps_at_its_window_dropping_the_oldest() {
        let mut log = ChatLog::default();
        for n in 0..=CHAT_LOG_CAP {
            log.push([1; 32], vec![u8::try_from(n).unwrap_or(0)]);
        }
        assert_eq!(log.entries.len(), CHAT_LOG_CAP);
        assert_eq!(log.entries[0].1, vec![1]);
    }

    #[test]
    fn an_empty_log_reads_as_default_and_round_trips() {
        assert_eq!(
            ChatLog::from_bytes(&[]).expect("empty data decodes"),
            ChatLog::default()
        );
        let mut log = ChatLog::default();
        log.push([3; 32], b"hello".to_vec());
        assert_eq!(
            ChatLog::from_bytes(&log.to_bytes()).expect("log decodes"),
            log
        );
    }
}
