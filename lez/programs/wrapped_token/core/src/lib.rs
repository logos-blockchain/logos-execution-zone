//! Core types for the wrapped-token program, the destination side of the
//! cross-zone bridge. Only the cross-zone inbox may mint; the guest enforces
//! this by reading the authorized minter from a genesis-seeded config account.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

/// The most one mint may credit.
///
/// The peer zone chooses the amount and the balance is a `u128`, so unbounded
/// one delivery pins a holding near the maximum, every later honest mint
/// overflows into a guest panic, and the holding is bricked for inbound
/// transfers at a cost of one message. The cap does not remove that ceiling, it
/// makes reaching it cost 2^64 deliveries instead of one.
///
/// `u64::MAX` is the bridge's bound, not one native balances obey. `bridge_lock`
/// refuses a larger amount at the source so it fails before escrowing.
pub const MAX_MINT_AMOUNT: u128 = 0xFFFF_FFFF_FFFF_FFFF;

const CONFIG_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/WrappedTokenConfig/00/";
const HOLDING_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/WrappedTokenHold/00000";
/// Raw 32-byte zone (channel) id, matching the inbox's.
pub type ZoneId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Credit `amount` wrapped tokens to `recipient`'s holding. Delivered only by
    /// the cross-zone inbox, and only for a peer source this token authorizes.
    ///
    /// Required accounts (3): the source marker, the wrapped-token config PDA,
    /// then the recipient's holding PDA.
    Mint { recipient: [u8; 32], amount: u128 },
    /// Pins the minter and the peer sources it may mint for, written once into a
    /// default config PDA at genesis. A re-run holding anything different is
    /// refused; an identical one is a no-op, which is what genesis replay does.
    ///
    /// Required accounts (1): the wrapped-token config PDA.
    InitConfig(WrappedTokenConfig),
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

/// Who may mint, and which peer sources they may mint for.
///
/// The source list is what makes this token authorize its own inbound value
/// rather than trusting a central route table to have done it. Borsh because the
/// list is variable length.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct WrappedTokenConfig {
    /// The program allowed to call `Mint`: the cross-zone inbox.
    pub minter: ProgramId,
    /// The program allowed to reach `UpdateSources` and `RenounceAuthority`
    /// through a chained call, or `None` for top-level only.
    ///
    /// Exists because a PDA cannot sign: a program-held authority acts only by
    /// its own program delegating it on a chained call. Unset closes the ambient
    /// path where any program the authority signed for could rewrite the list.
    pub governance: Option<ProgramId>,
    /// The account allowed to change `sources`, or `None` for a list fixed at
    /// genesis.
    ///
    /// Whoever holds this can authorize a new source, and a source can mint, so
    /// its compromise is theft rather than delay; it is seeded unset until there
    /// is a governance program worth pointing it at. An `AccountId` rather than
    /// a key, so a PDA of such a program can hold it and act by delegation.
    pub authority: Option<AccountId>,
    /// The `(src_zone, src_program_id)` pairs a mint may originate from. Empty on
    /// a zone with no peers, which authorizes nothing.
    pub sources: Vec<(ZoneId, ProgramId)>,
}

impl WrappedTokenConfig {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("wrapped-token config serializes")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// PDA holding the authorized minter program id (the cross-zone inbox), seeded at
/// genesis so the guest can pin its caller without importing the inbox image id.
#[must_use]
pub fn config_account_id(wrapped_token_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&wrapped_token_id, &config_seed())
}

#[must_use]
pub const fn config_seed() -> PdaSeed {
    PdaSeed::new(CONFIG_SEED_DOMAIN)
}

/// PDA holding one recipient's wrapped-token balance.
#[must_use]
pub fn holding_account_id(wrapped_token_id: ProgramId, recipient: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(&wrapped_token_id, &holding_seed(recipient))
}

#[must_use]
pub fn holding_seed(recipient: &[u8; 32]) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&HOLDING_SEED_DOMAIN);
    bytes[32..].copy_from_slice(recipient);
    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

/// Reads a wrapped-token balance from account data; empty data is a zero balance.
#[must_use]
pub fn read_balance(data: &[u8]) -> u128 {
    if data.len() < 16 {
        return 0;
    }
    u128::from_le_bytes(data[..16].try_into().unwrap_or_else(|_| unreachable!()))
}

#[must_use]
pub const fn balance_bytes(amount: u128) -> [u8; 16] {
    amount.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips() {
        let config = WrappedTokenConfig {
            minter: [1, 2, 3, 4, 5, 6, 7, 8],
            governance: Some([2; 8]),
            authority: Some(AccountId::new([5; 32])),
            sources: vec![([7; 32], [9; 8]), ([8; 32], [4; 8])],
        };
        assert_eq!(
            WrappedTokenConfig::from_bytes(&config.to_bytes()),
            Some(config)
        );
    }

    /// An unclaimed config reads as empty, which must not decode to a config that
    /// authorizes anything.
    #[test]
    fn an_empty_config_does_not_decode() {
        assert_eq!(WrappedTokenConfig::from_bytes(&[]), None);
    }

    /// The peer's `bridge_lock` serializes `Mint` into the emission payload, so
    /// its tag word is wire format.
    #[test]
    fn mint_is_the_first_variant() {
        let mint = Instruction::Mint {
            recipient: [3; 32],
            amount: 1,
        };
        let words = risc0_zkvm::serde::to_vec(&mint).expect("Mint serializes");
        assert_eq!(words[0], 0);
    }

    #[test]
    fn balance_round_trips() {
        assert_eq!(read_balance(&balance_bytes(42)), 42);
        assert_eq!(read_balance(&[]), 0);
    }

    #[test]
    fn holding_is_unique_per_recipient() {
        let id: ProgramId = [9; 8];
        assert_ne!(
            holding_account_id(id, &[1; 32]),
            holding_account_id(id, &[2; 32])
        );
        assert_eq!(
            holding_account_id(id, &[1; 32]),
            holding_account_id(id, &[1; 32])
        );
    }
}
