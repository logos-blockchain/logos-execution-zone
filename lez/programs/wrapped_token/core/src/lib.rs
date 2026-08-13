//! Core types for the wrapped-token program, the destination side of the
//! cross-zone bridge. Only the cross-zone inbox may mint; the guest enforces
//! this by reading the authorized minter from a genesis-seeded config account.

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Credit `amount` wrapped tokens to `recipient`'s holding. Delivered only by
    /// the cross-zone inbox.
    ///
    /// Required accounts (2): the wrapped-token config PDA, then the recipient's
    /// holding PDA.
    Mint { recipient: [u8; 32], amount: u128 },
    /// Pins `minter` (the cross-zone inbox) as the authorized minter, written once
    /// into a default config PDA at genesis. The guest refuses a non-default
    /// pre-state, so it cannot be re-run to hijack the minter.
    ///
    /// Required accounts (1): the wrapped-token config PDA.
    InitConfig { minter: ProgramId },
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

/// Encodes the authorized minter program id for the config account's data.
#[must_use]
pub fn minter_bytes(minter: ProgramId) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (word, chunk) in minter.iter().zip(bytes.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Decodes the authorized minter program id from the config account's data.
#[must_use]
pub fn read_minter(data: &[u8]) -> Option<ProgramId> {
    if data.len() < 32 {
        return None;
    }
    let mut minter = [0_u32; 8];
    for (word, chunk) in minter.iter_mut().zip(data[..32].chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap_or_else(|_| unreachable!()));
    }
    Some(minter)
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
    fn minter_round_trips() {
        let minter: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(read_minter(&minter_bytes(minter)), Some(minter));
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
