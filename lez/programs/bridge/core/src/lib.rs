use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::PdaSeed;
use lee_core::{account::AccountId, program::ProgramId};

const BRIDGE_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/BridgeSeed/0000000000/";
const DEPOSIT_RECEIPT_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeDepositReceipt/0";

#[derive(BorshSerialize, BorshDeserialize)]
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
        vault_program_id: ProgramId,
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

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Deposit {
    pub l1_deposit_op_id: [u8; 32],
    pub vault_program_id: ProgramId,
    pub recipient_id: AccountId,
    pub amount: u64,
}

impl Deposit {
    pub const SELECTOR: [u8; 8] = [0xcd, 0x49, 0x9a, 0xe5, 0x48, 0xcd, 0xf2, 0x3d];
    pub const SELECTOR_NAME: &str = "bridge::Deposit";

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Deposit serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Withdraw {
    pub sender_id: AccountId,
    pub amount: u64,
    pub bedrock_account_pk: [u8; 32],
}

impl Withdraw {
    pub const SELECTOR: [u8; 8] = [0x87, 0x4b, 0x49, 0x79, 0x94, 0x7b, 0x40, 0xe2];
    pub const SELECTOR_NAME: &str = "bridge::Withdraw";

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Withdraw serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
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

    #[test]
    fn event_selectors_match_their_derivations() {
        use sha2::Digest as _;

        assert_eq!(
            Deposit::SELECTOR[..],
            sha2::Sha256::digest(Deposit::SELECTOR_NAME.as_bytes())[..8]
        );
        assert_eq!(
            Withdraw::SELECTOR[..],
            sha2::Sha256::digest(Withdraw::SELECTOR_NAME.as_bytes())[..8]
        );
    }

    #[test]
    fn events_round_trip_through_bytes() {
        let deposit = Deposit {
            l1_deposit_op_id: [2; 32],
            vault_program_id: [6; 8],
            recipient_id: AccountId::new([0; 32]),
            amount: 1,
        };
        let withdraw = Withdraw {
            sender_id: AccountId::new([3; 32]),
            amount: 4,
            bedrock_account_pk: [5; 32],
        };

        assert_eq!(Deposit::from_bytes(&deposit.to_bytes()).unwrap(), deposit);
        assert_eq!(
            Withdraw::from_bytes(&withdraw.to_bytes()).unwrap(),
            withdraw
        );
    }

    #[test]
    fn deposit_wire_bytes_are_pinned() {
        let deposit = Deposit {
            l1_deposit_op_id: [0; 32],
            vault_program_id: [1; 8],
            recipient_id: AccountId::new([2; 32]),
            amount: 3,
        };

        let mut expected = vec![0; 32];
        expected.extend([1, 0, 0, 0].repeat(8));
        expected.extend([2; 32]);
        expected.extend(3_u64.to_le_bytes());

        assert_eq!(deposit.to_bytes(), expected);
    }
}
