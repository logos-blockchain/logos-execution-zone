//! Protocol constants.
//!
//! Values from SPECS.md §Parameters; changing any of them is a
//! protocol-version change. Derived constants use `checked_*` const-eval
//! (via small helper functions below) instead of raw operators, so a
//! mistake here is a compile-time panic rather than a silent wrap.

use crate::error::FeeError;

/// Execution gas target per block.
pub const TARGET_GAS_EXEC: u64 = 5_000_000;
/// Execution gas cap per block (= 2 * `TARGET_GAS_EXEC`; checked at genesis).
pub const MAX_GAS_EXEC: u64 = 10_000_000;
/// Storage bytes target per block.
pub const TARGET_GAS_STOR: u64 = 500_000;
/// Storage bytes cap per block (= 2 * `TARGET_GAS_STOR`; checked at genesis).
pub const MAX_GAS_STOR: u64 = 1_000_000;
/// Execution adjustment denominator (max +-12.5% move per block).
pub const D_EXEC: u64 = 8;
/// Storage adjustment denominator (max +-12.5% move per block).
pub const D_STOR: u64 = 8;
/// Minimum execution base fee, atomic units per gas.
pub const BASE_FEE_EXEC_MIN: u64 = 8;
/// Minimum storage base fee, atomic units per byte.
pub const BASE_FEE_STOR_MIN: u64 = 8;
/// Saturation cap for the execution base fee: `u64::MAX / MAX_GAS_EXEC`.
pub const BASE_FEE_EXEC_MAX: u64 = const_div(u64::MAX, MAX_GAS_EXEC);
/// Saturation cap for the storage base fee: `u64::MAX / MAX_GAS_STOR`.
pub const BASE_FEE_STOR_MAX: u64 = const_div(u64::MAX, MAX_GAS_STOR);
/// Payout slots per unit of base revenue, and the width of `FeeState::window`.
pub const SMOOTHING_WINDOW: usize = 50;
/// Execution gas of every private transaction.
pub const PRIVATE_VERIFY_GAS: u64 = 409_764;
/// Proof bytes inside every private transaction.
// provisional: re-pinned by T3/T5 measurement
pub const PROOF_BYTES: u64 = 223_551;
/// Payload size every private transaction is padded to.
// provisional: re-pinned by T3/T5 measurement
pub const PRIVATE_PAD_BYTES: u64 = 512;
/// Canonical serialized size of every private transaction (envelope, proof,
/// padded payload). The wire format MUST make this size constant.
// provisional: re-pinned by T3/T5 measurement, together with PRIVATE_PAD_BYTES
// and PROOF_BYTES above.
pub const PRIVATE_GAS_STOR: u64 = const_add(PRIVATE_PAD_BYTES, PROOF_BYTES);

/// Total supply, atomic units. Bounds every real balance; below 2^64, so no
/// balance or credit can overflow 128-bit arithmetic.
pub const TOTAL_SUPPLY: u128 = 10_000_000_000_000_000_000;

// Compile-time guard: caught regardless of build profile. `validate_genesis_params`
// below is the runtime-checked counterpart used by fallible constructors.
const _: () = assert!(MAX_GAS_EXEC == const_mul(2, TARGET_GAS_EXEC));
const _: () = assert!(MAX_GAS_STOR == const_mul(2, TARGET_GAS_STOR));

const fn const_div(a: u64, b: u64) -> u64 {
    match a.checked_div(b) {
        Some(v) => v,
        None => panic!("division by zero in protocol constant"),
    }
}

const fn const_add(a: u64, b: u64) -> u64 {
    match a.checked_add(b) {
        Some(v) => v,
        None => panic!("overflow in protocol constant"),
    }
}

const fn const_mul(a: u64, b: u64) -> u64 {
    match a.checked_mul(b) {
        Some(v) => v,
        None => panic!("overflow in protocol constant"),
    }
}

/// Checks the genesis invariant `MAX_GAS_r == 2 * TARGET_GAS_r` for both
/// resources at runtime (SPECS §Genesis).
///
/// Unlike a bare `assert!`, this returns a `Result` the caller must handle,
/// so the check cannot be compiled or skipped away in a release profile.
///
/// # Errors
///
/// Returns [`FeeError::InvalidGenesisParams`] if either resource's cap is not
/// exactly twice its target.
pub const fn validate_genesis_params() -> Result<(), FeeError> {
    if MAX_GAS_EXEC == const_mul(2, TARGET_GAS_EXEC)
        && MAX_GAS_STOR == const_mul(2, TARGET_GAS_STOR)
    {
        Ok(())
    } else {
        Err(FeeError::InvalidGenesisParams)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_params_are_valid() {
        assert_eq!(validate_genesis_params(), Ok(()));
    }

    #[test]
    fn private_gas_stor_matches_spec_value() {
        assert_eq!(PRIVATE_GAS_STOR, 224_063);
    }

    #[test]
    fn base_fee_max_matches_spec_value() {
        assert_eq!(BASE_FEE_EXEC_MAX, 1_844_674_407_370);
        assert_eq!(BASE_FEE_STOR_MAX, 18_446_744_073_709);
    }
}
