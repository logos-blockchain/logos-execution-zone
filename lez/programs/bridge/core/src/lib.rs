pub use lee_core::program::PdaSeed;
use lee_core::{account::AccountId, program::ProgramId};
use serde::{Deserialize, Serialize};

const BRIDGE_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/BridgeSeed/0000000000/";
const DEPOSIT_RECEIPT_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeDepositReceipt/0";

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfers native tokens from the bridge PDA account to a recipient vault,
    /// exactly once per `l1_deposit_op_id`.
    ///
    /// Required accounts (3):
    /// - Bridge PDA account
    /// - Recipient vault PDA account
    /// - Deposit-receipt PDA account, derived from `l1_deposit_op_id`. Its existence records that
    ///   this op id was already minted; a second application of the same op id finds it present and
    ///   transfers nothing.
    Deposit {
        /// Deposit OP ID from L1, stored here to pin each [`Deposit`](Instruction::Deposit) to a
        /// Deposit Event on L1.
        l1_deposit_op_id: [u8; 32],
        /// This program's own image id. The guest cannot learn this at runtime, so the trusted
        /// caller supplies it to recompute the bridge and receipt PDAs; a wrong value only fails
        /// the guest's own self-consistency assertions, since real authorization is
        /// independently enforced by the state layer against the account's `program_owner`.
        self_program_id: ProgramId,
        /// The vault program's own image id, used to derive the expected recipient vault PDA.
        vault_program_id: ProgramId,
        /// The vault program's real dispatch address, used as the chained-call target.
        vault_account_id: AccountId,
        recipient_id: AccountId,
        amount: u64,
    },

    /// Transfers native tokens from a user account to the bridge PDA account.
    ///
    /// Required accounts (2):
    /// - Sender account
    /// - Bridge PDA account
    ///
    /// `bedrock_account_pk` is consumed by the Sequencer and is not used by the Bridge program
    /// logic.
    Withdraw {
        amount: u64,
        bedrock_account_pk: [u8; 32],
    },
}

#[must_use]
pub const fn compute_bridge_seed() -> PdaSeed {
    PdaSeed::new(BRIDGE_SEED_DOMAIN_SEPARATOR)
}

#[must_use]
pub fn compute_bridge_account_id(bridge_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&bridge_program_id, &compute_bridge_seed())
}

/// Seed of the deposit-receipt PDA for `l1_deposit_op_id`, exposed so the guest
/// can claim the account. Domain-separated from [`compute_bridge_seed`].
#[must_use]
pub fn deposit_receipt_seed(l1_deposit_op_id: [u8; 32]) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&DEPOSIT_RECEIPT_SEED_DOMAIN);
    bytes[32..].copy_from_slice(&l1_deposit_op_id);

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

/// The deposit-receipt PDA whose existence marks `l1_deposit_op_id` as minted.
#[must_use]
pub fn deposit_receipt_account_id(
    bridge_program_id: ProgramId,
    l1_deposit_op_id: [u8; 32],
) -> AccountId {
    AccountId::for_public_pda(&bridge_program_id, &deposit_receipt_seed(l1_deposit_op_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRIDGE_ID: ProgramId = [7; 8];

    #[test]
    fn receipt_id_is_deterministic_per_op_id() {
        let op = [3_u8; 32];
        assert_eq!(
            deposit_receipt_account_id(BRIDGE_ID, op),
            deposit_receipt_account_id(BRIDGE_ID, op)
        );
    }

    #[test]
    fn distinct_op_ids_and_domains_do_not_collide() {
        let a = deposit_receipt_account_id(BRIDGE_ID, [1; 32]);
        let b = deposit_receipt_account_id(BRIDGE_ID, [2; 32]);
        assert_ne!(a, b, "different op ids must derive different receipts");
        // The op-id-derived seed must not alias the plain bridge PDA, even if an
        // op id ever equals the bridge seed's raw bytes.
        assert_ne!(
            deposit_receipt_account_id(BRIDGE_ID, *compute_bridge_seed().as_bytes()),
            compute_bridge_account_id(BRIDGE_ID)
        );
    }
}
