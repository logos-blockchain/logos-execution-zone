//! Core types for the bridge-lock program, the source side of the cross-zone
//! token bridge. A holder locks part of their balance into an escrow and emits a
//! cross-zone message minting the wrapped token on the target zone.

use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

const ESCROW_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockEscrow/0000/";
const CONFIG_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockCfg/0000000/";

/// Variants are append-only. risc0 serde encodes the variant as a bare leading
/// tag word, so inserting one ahead of `Lock` shifts every existing encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Lock `amount` of the holder's balance and emit a cross-zone message
    /// minting the wrapped token on `target_zone`.
    ///
    /// `target_program_id` and `target_accounts` are supplied though the guest
    /// accepts one value for each: `cross_zone::extract_emission` reads them off
    /// the transaction, decoding every emitter through one shape.
    ///
    /// `target_zone` is the caller's, so a lock to a zone that will not route it
    /// escrows and never mints. TODO: bound it source-side.
    ///
    /// Required accounts (4): config PDA, holder holding (authorized), escrow
    /// PDA, outbox PDA.
    Lock {
        /// This program's own image id. The guest cannot learn this at runtime, so the trusted
        /// caller supplies it to recompute the config and escrow PDAs; a wrong value only fails
        /// the guest's own self-consistency assertions, since real authorization is
        /// independently enforced by the state layer against the account's `program_owner`.
        self_program_id: ProgramId,
        amount: u128,
        target_zone: [u8; 32],
        target_program_id: ProgramId,
        target_accounts: Vec<[u8; 32]>,
        payload: Vec<u8>,
        ordinal: u32,
    },
    /// Pins the outbox program and the mint target, written once into a default
    /// config PDA at genesis. A re-run naming different programs is refused; an
    /// identical one is a no-op, which is what genesis replay does.
    ///
    /// Required accounts (1): the config PDA.
    InitConfig {
        /// See [`Lock::self_program_id`](Instruction::Lock).
        self_program_id: ProgramId,
        /// The outbox program's real dispatch address.
        outbox_account_id: AccountId,
        /// The outbox program's own image id, supplied back to it as its `self_program_id` when
        /// dispatching `cross_zone_outbox_core::Instruction::Emit`.
        outbox_program_id: ProgramId,
        target_program_id: ProgramId,
    },
}

/// PDA accumulating all locked balance on this zone.
#[must_use]
pub fn escrow_account_id(bridge_lock_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &escrow_seed())
}

#[must_use]
pub const fn escrow_seed() -> PdaSeed {
    PdaSeed::new(ESCROW_SEED_DOMAIN)
}

/// PDA holding the outbox's dispatch address and the mint target, seeded at
/// genesis so the guest can pin both without importing their image ids.
#[must_use]
pub fn config_account_id(bridge_lock_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &config_seed())
}

#[must_use]
pub const fn config_seed() -> PdaSeed {
    PdaSeed::new(CONFIG_SEED_DOMAIN)
}

/// Encodes the pinned outbox dispatch address, outbox image id, and mint target
/// for the config account's data.
#[must_use]
pub fn config_bytes(
    outbox_account_id: AccountId,
    outbox_program_id: ProgramId,
    target_program_id: ProgramId,
) -> [u8; 96] {
    let mut bytes = [0_u8; 96];
    bytes[..32].copy_from_slice(outbox_account_id.value());
    for (word, chunk) in outbox_program_id
        .iter()
        .chain(target_program_id.iter())
        .zip(bytes[32..].chunks_exact_mut(4))
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Decodes the pinned outbox dispatch address, outbox image id, and mint target
/// from the config account's data.
#[must_use]
pub fn read_config(data: &[u8]) -> Option<(AccountId, ProgramId, ProgramId)> {
    if data.len() < 96 {
        return None;
    }
    assert!(data.len() >= 96);
    let outbox_account_id =
        AccountId::new(data[..32].try_into().unwrap_or_else(|_| unreachable!()));
    let mut ids = [0_u32; 16];
    for (word, chunk) in ids.iter_mut().zip(data[32..96].chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap_or_else(|_| unreachable!()));
    }
    let (outbox_program_id, target_program_id) = ids.split_at(8);
    Some((
        outbox_account_id,
        outbox_program_id
            .try_into()
            .unwrap_or_else(|_| unreachable!()),
        target_program_id
            .try_into()
            .unwrap_or_else(|_| unreachable!()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escrow_is_stable() {
        let id: ProgramId = [4; 8];
        assert_eq!(escrow_account_id(id), escrow_account_id(id));
    }

    #[test]
    fn config_ids_round_trip() {
        let outbox_account_id = AccountId::new([3; 32]);
        let outbox_program_id: ProgramId = [4; 8];
        let target: ProgramId = [5; 8];
        assert_eq!(
            read_config(&config_bytes(outbox_account_id, outbox_program_id, target)),
            Some((outbox_account_id, outbox_program_id, target))
        );
    }

    /// `extract_emission` decodes `Lock` off peer transactions, so its tag word is
    /// wire format: a variant inserted ahead of it would silently shift every
    /// existing encoding.
    #[test]
    fn lock_is_the_first_variant() {
        let lock = Instruction::Lock {
            self_program_id: [2; 8],
            amount: 1,
            target_zone: [7; 32],
            target_program_id: [1; 8],
            target_accounts: vec![],
            payload: vec![],
            ordinal: 0,
        };
        let words = risc0_zkvm::serde::to_vec(&lock).expect("Lock serializes");
        assert_eq!(words[0], 0);
    }
}
