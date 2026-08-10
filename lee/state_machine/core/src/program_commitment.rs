use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::program::ProgramId;

/// A commitment to a deployed program, appended to the `ProgramCommitmentDigest` on every
/// program-deployment transaction. See `upgrade_proposal.md`.
///
/// This is Phase 1's bootstrap definition: the commitment is simply `program_id`'s bytes, with
/// no domain separation and no mixing in of `version`/`upgrade_auth` — neither field exists on
/// `Program` yet. This lets the digest/membership-proof machinery (this type, the Merkle tree
/// wrapping it, and eventually the privacy-preserving circuit's membership check) be built and
/// tested before the real formula is meaningful. It is superseded by
/// `Sha256(domain || program_id || version || update_id)` once `Program` gains real upgrade
/// fields (see the proposal's "Program commitments" section and its Phase 2 PR 4).
#[derive(Copy, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)
)]
pub struct ProgramCommitment(pub(super) [u8; 32]);

impl ProgramCommitment {
    /// Phase 1 bootstrap constructor — see the type's own doc comment.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "i is bounded 0..8 by ProgramId's fixed length, so i * 4 is always in 0..32 \
                  and never overflows or produces an out-of-bounds index"
    )]
    pub fn for_program_id(program_id: ProgramId) -> Self {
        let mut bytes = [0_u8; 32];
        for (i, word) in program_id.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::ProgramCommitment;

    #[test]
    fn for_program_id_is_deterministic() {
        let program_id: crate::program::ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            ProgramCommitment::for_program_id(program_id),
            ProgramCommitment::for_program_id(program_id)
        );
    }

    #[test]
    fn for_program_id_differs_for_different_ids() {
        let a: crate::program::ProgramId = [1, 0, 0, 0, 0, 0, 0, 0];
        let b: crate::program::ProgramId = [2, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(
            ProgramCommitment::for_program_id(a),
            ProgramCommitment::for_program_id(b)
        );
    }

    #[test]
    fn for_program_id_matches_le_byte_encoding() {
        let program_id: crate::program::ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut expected = [0_u8; 32];
        for (i, word) in program_id.iter().enumerate() {
            expected[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            ProgramCommitment::for_program_id(program_id).to_byte_array(),
            expected
        );
    }
}
