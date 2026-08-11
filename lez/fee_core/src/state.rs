//! Fee-subsystem state (SPECS.md §State), minus `height`: the chain's
//! `block_id` already serves as height, so `FeeState` doesn't duplicate it.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    error::FeeError,
    params::{BASE_FEE_EXEC_MIN, BASE_FEE_STOR_MIN, SMOOTHING_WINDOW, validate_genesis_params},
};

/// Fee-subsystem state carried across blocks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeState {
    /// Execution base fee for the current block.
    pub base_fee_exec: u64,
    /// Storage base fee for the current block.
    pub base_fee_stor: u64,
    /// Settled base revenue not yet paid out.
    pub escrow: u128,
    /// Base revenue of the last `SMOOTHING_WINDOW` blocks, oldest-evicting
    /// ring buffer indexed by `cursor`.
    pub window: [u128; SMOOTHING_WINDOW],
    /// Index of the oldest slot in `window` (the next slot to be
    /// overwritten). In `[0, SMOOTHING_WINDOW)`.
    pub cursor: u8,
    /// Payout division remainder, in `[0, SMOOTHING_WINDOW)`.
    pub payout_carry: u128,
}

impl FeeState {
    /// The genesis state (SPECS §Genesis): both base fees at their minimum,
    /// zero escrow, a zero-filled window, and no carry.
    ///
    /// # Errors
    ///
    /// Returns [`FeeError::InvalidGenesisParams`] if the compiled-in
    /// parameters fail `MAX_GAS_r == 2 * TARGET_GAS_r` for either resource.
    /// Unreachable with this crate's shipped [`crate::params`] values; kept
    /// fallible so the check is never optimized away.
    pub const fn genesis() -> Result<Self, FeeError> {
        match validate_genesis_params() {
            Ok(()) => Ok(Self {
                base_fee_exec: BASE_FEE_EXEC_MIN,
                base_fee_stor: BASE_FEE_STOR_MIN,
                escrow: 0,
                window: [0; SMOOTHING_WINDOW],
                cursor: 0,
                payout_carry: 0,
            }),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{BASE_FEE_EXEC_MIN, BASE_FEE_STOR_MIN};

    #[test]
    fn genesis_matches_spec() {
        let state = FeeState::genesis().unwrap();
        assert_eq!(state.base_fee_exec, BASE_FEE_EXEC_MIN);
        assert_eq!(state.base_fee_stor, BASE_FEE_STOR_MIN);
        assert_eq!(state.escrow, 0);
        assert_eq!(state.window, [0_u128; SMOOTHING_WINDOW]);
        assert_eq!(state.cursor, 0);
        assert_eq!(state.payout_carry, 0);
    }

    #[test]
    fn genesis_state_roundtrips_through_borsh() {
        let state = FeeState::genesis().unwrap();
        let bytes = borsh::to_vec(&state).unwrap();
        let decoded: FeeState = borsh::from_slice(&bytes).unwrap();
        assert_eq!(state, decoded);
    }
}
