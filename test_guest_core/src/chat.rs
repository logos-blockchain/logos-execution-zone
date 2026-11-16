//! Types for the `zone_chat` test guest: a program with no builtin privileges
//! that both sends across zones and is a conforming receiver.

use borsh::{BorshDeserialize, BorshSerialize};
pub use cross_zone_receiver_core::{
    Delivery, INIT_CONFIG_TAG, ReceiverConfig, ZoneId, init_config_instruction_bytes,
    receiver_config_account_id, receiver_config_seed,
};
use lee_core::{
    account::{AccountId, Actor},
    program::PdaSeed,
};

const CHAT_LOG_SEED: [u8; 32] = *b"/LEZ/test/ZoneChatLog/0000000000";

/// Newest-last entries kept in the log; older ones are dropped.
pub const CHAT_LOG_CAP: usize = 64;

/// `zone_chat`'s instruction set.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ChatMessage {
    /// Send `payload` to `target` in `target_zone`, declaring `accounts` for
    /// its delivery.
    Post {
        target_zone: ZoneId,
        target: Actor,
        accounts: Vec<Actor>,
        payload: Vec<u8>,
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
