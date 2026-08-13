//! Base-fee update (SPECS.md §Base-fee update).
//!
//! Each resource's base fee adjusts independently after every block, by a
//! deviation-clamped delta with a guaranteed +1 up-step and no down-step
//! minimum, saturating to `[lo, hi]`.

use std::cmp::Ordering;

use crate::{
    params::{
        BASE_FEE_EXEC_MAX, BASE_FEE_EXEC_MIN, BASE_FEE_STOR_MAX, BASE_FEE_STOR_MIN, D_EXEC, D_STOR,
        TARGET_GAS_EXEC, TARGET_GAS_STOR,
    },
    state::FeeState,
};

/// Both base fees one block on, at the gas the block used.
///
/// The single place each resource is wired to its own target, denominator and saturation bounds.
/// The block transition moves the fee state through [`step_base_fees`]; anything that *quotes* the
/// next block's prices without moving state (the sequencer's fee RPC) reads them here, so a quote
/// cannot drift from what the transition will actually do.
#[must_use]
pub fn stepped_base_fees(state: &FeeState, gas_used_exec: u64, gas_used_stor: u64) -> (u64, u64) {
    (
        next_base_fee(
            state.base_fee_exec,
            gas_used_exec,
            TARGET_GAS_EXEC,
            D_EXEC,
            BASE_FEE_EXEC_MIN,
            BASE_FEE_EXEC_MAX,
        ),
        next_base_fee(
            state.base_fee_stor,
            gas_used_stor,
            TARGET_GAS_STOR,
            D_STOR,
            BASE_FEE_STOR_MIN,
            BASE_FEE_STOR_MAX,
        ),
    )
}

/// Moves both base fees to their values for the next block (SPECS §Base-fee update).
pub fn step_base_fees(state: &mut FeeState, gas_used_exec: u64, gas_used_stor: u64) {
    let (base_fee_exec, base_fee_stor) = stepped_base_fees(state, gas_used_exec, gas_used_stor);
    state.base_fee_exec = base_fee_exec;
    state.base_fee_stor = base_fee_stor;
}

/// Computes the next base fee for one resource.
///
/// Takes the current value `b`, gas used `g`, `target`, adjustment
/// denominator `d`, and saturation bounds `[lo, hi]`. All arithmetic is
/// widened to `u128` for the deviation product; the result is narrowed back
/// to `u64` only after it is known to fit (the deviation clamp bounds
/// `delta` by `b / d <= b`).
#[must_use]
pub fn next_base_fee(b: u64, g: u64, target: u64, d: u64, lo: u64, hi: u64) -> u64 {
    match g.cmp(&target) {
        Ordering::Greater => {
            let deviation = g
                .checked_sub(target)
                .expect("g > target: checked by this match arm")
                .min(target);
            let delta = deviation_delta(b, deviation, target, d);
            let delta = u64::try_from(delta)
                .expect("delta <= b / d <= b, always fits u64")
                .max(1);
            hi.min(b.saturating_add(delta))
        }
        Ordering::Less => {
            let deviation = target
                .checked_sub(g)
                .expect("g < target: checked by this match arm")
                .min(target);
            let delta = deviation_delta(b, deviation, target, d);
            let delta = u64::try_from(delta).expect("delta <= b / d <= b, always fits u64");
            lo.max(
                b.checked_sub(delta)
                    .expect("delta <= b / d <= b, proven by the deviation clamp"),
            )
        }
        Ordering::Equal => b,
    }
}

/// `b * deviation / (target * d)`, widened to `u128` throughout (SPECS
/// §Base-fee update: "128-bit product"). `target` and `d` are protocol
/// constants and never zero for any call this crate makes.
fn deviation_delta(b: u64, deviation: u64, target: u64, d: u64) -> u128 {
    let numerator = u128::from(b)
        .checked_mul(u128::from(deviation))
        .expect("u64 * u64 widened to u128 cannot overflow");
    let denominator = u128::from(target)
        .checked_mul(u128::from(d))
        .expect("u64 * u64 widened to u128 cannot overflow");
    numerator
        .checked_div(denominator)
        .expect("target and d are nonzero protocol constants")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "test code, plain arithmetic is clearer"
    )]

    use super::*;
    use crate::params::{BASE_FEE_EXEC_MAX, BASE_FEE_EXEC_MIN, D_EXEC, TARGET_GAS_EXEC};

    #[test]
    fn unchanged_at_target() {
        assert_eq!(
            next_base_fee(
                1_000,
                TARGET_GAS_EXEC,
                TARGET_GAS_EXEC,
                D_EXEC,
                8,
                BASE_FEE_EXEC_MAX
            ),
            1_000
        );
    }

    #[test]
    fn rises_by_at_least_one_above_target() {
        // One unit above target: deviation = 1, delta rounds to 0 but the
        // max(1, .) floor guarantees a +1 rise (liveness property).
        let next = next_base_fee(
            8,
            TARGET_GAS_EXEC + 1,
            TARGET_GAS_EXEC,
            D_EXEC,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(next, 9);
    }

    #[test]
    fn small_deviation_below_target_can_freeze() {
        // Asymmetric-at-small-prices property: one unit below target usually
        // does not move the price (no matching +1 floor on the down-step).
        let next = next_base_fee(
            8,
            TARGET_GAS_EXEC - 1,
            TARGET_GAS_EXEC,
            D_EXEC,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(next, 8);
    }

    #[test]
    fn move_is_bounded_by_b_over_d() {
        // Full usage (g = MAX_GAS = 2*target => deviation clamps to target):
        // delta should equal b / d exactly at large b (b divisible by d).
        let b = 1_600;
        let next = next_base_fee(
            b,
            2 * TARGET_GAS_EXEC,
            TARGET_GAS_EXEC,
            D_EXEC,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(next - b, b / D_EXEC);
    }

    #[test]
    fn saturates_at_hi() {
        assert_eq!(
            next_base_fee(
                BASE_FEE_EXEC_MAX,
                2 * TARGET_GAS_EXEC,
                TARGET_GAS_EXEC,
                D_EXEC,
                BASE_FEE_EXEC_MIN,
                BASE_FEE_EXEC_MAX
            ),
            BASE_FEE_EXEC_MAX
        );
    }

    #[test]
    fn saturates_at_lo() {
        assert_eq!(
            next_base_fee(
                BASE_FEE_EXEC_MIN,
                0,
                TARGET_GAS_EXEC,
                D_EXEC,
                BASE_FEE_EXEC_MIN,
                BASE_FEE_EXEC_MAX
            ),
            BASE_FEE_EXEC_MIN
        );
    }

    #[test]
    fn never_moves_more_than_bound_across_a_sweep() {
        // Invariant 2: bounded adjustment, swept over a range of usages.
        let b = 1_000_000_u64;
        let bound = (b / D_EXEC).max(1);
        for g in (0..=2 * TARGET_GAS_EXEC).step_by(37_001) {
            let next = next_base_fee(
                b,
                g,
                TARGET_GAS_EXEC,
                D_EXEC,
                BASE_FEE_EXEC_MIN,
                BASE_FEE_EXEC_MAX,
            );
            let moved = next.abs_diff(b);
            assert!(moved <= bound, "g={g} moved={moved} bound={bound}");
        }
    }
}
