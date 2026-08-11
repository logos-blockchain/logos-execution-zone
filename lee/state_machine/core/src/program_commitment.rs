use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::program::ProgramId;

#[derive(Copy, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)
)]
pub struct ProgramCommitment(pub(super) [u8; 32]);

impl ProgramCommitment {
    #[must_use]
    pub fn new(program_id: ProgramId) -> Self {
        let mut bytes = Vec::with_capacity(32);
        for word in program_id {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        Self(bytes.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::ProgramCommitment;

    #[test]
    fn new_is_deterministic() {
        let program_id: crate::program::ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            ProgramCommitment::new(program_id),
            ProgramCommitment::new(program_id)
        );
    }

    #[test]
    fn new_differs_for_different_ids() {
        let a: crate::program::ProgramId = [1, 0, 0, 0, 0, 0, 0, 0];
        let b: crate::program::ProgramId = [2, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(ProgramCommitment::new(a), ProgramCommitment::new(b));
    }

    #[test]
    fn new_matches_le_byte_encoding() {
        let program_id: crate::program::ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut expected = Vec::with_capacity(32);
        for word in program_id {
            expected.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            ProgramCommitment::new(program_id).to_byte_array(),
            expected.as_slice()
        );
    }
}
