use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::ProgramId};

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

#[cfg(test)]
mod tests {
    use super::*;

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
