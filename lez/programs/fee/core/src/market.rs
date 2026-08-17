//! The dual fee market: protocol constants and the base-fee controller.
//!
//! All values are protocol constants; changing any is a protocol-version
//! change.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "spec-mandated integer math: products are widened to u128 and subtractions are \
              guarded by the enclosing comparison"
)]

use core::cmp::Ordering;

pub const TARGET_GAS_EXEC: u64 = 5_000_000;
pub const MAX_GAS_EXEC: u64 = 10_000_000;
pub const D_EXEC: u64 = 8;
pub const BASE_FEE_EXEC_MIN: u64 = 8;
pub const BASE_FEE_EXEC_MAX: u64 = u64::MAX / MAX_GAS_EXEC;

pub const TARGET_GAS_STOR: u64 = 500_000;
pub const MAX_GAS_STOR: u64 = 1_000_000;
pub const D_STOR: u64 = 8;
pub const BASE_FEE_STOR_MIN: u64 = 8;
pub const BASE_FEE_STOR_MAX: u64 = u64::MAX / MAX_GAS_STOR;

pub const SMOOTHING_WINDOW: usize = 50;

// Genesis validation: the ±12.5% bound and elasticity framing assume
// MAX = 2·TARGET for both resources.
const _: () = assert!(MAX_GAS_EXEC == 2 * TARGET_GAS_EXEC);
const _: () = assert!(MAX_GAS_STOR == 2 * TARGET_GAS_STOR);

/// One base-fee update. The deviation clamp bounds the move to `max(1, b / d)`;
/// products are widened to 128 bits so the cap price cannot overflow; the
/// result saturates into `[lo, hi]`.
#[must_use]
pub fn next_base_fee(b: u64, g: u64, target: u64, d: u64, lo: u64, hi: u64) -> u64 {
    match g.cmp(&target) {
        Ordering::Greater => {
            let deviation = (g - target).min(target);
            let delta = ((u128::from(b) * u128::from(deviation))
                / (u128::from(target) * u128::from(d)))
            .max(1);
            let delta = u64::try_from(delta).expect("delta is at most b/d, which fits u64");
            hi.min(b.saturating_add(delta))
        }
        Ordering::Less => {
            let deviation = (target - g).min(target);
            let delta =
                (u128::from(b) * u128::from(deviation)) / (u128::from(target) * u128::from(d));
            let delta = u64::try_from(delta).expect("delta is at most b/d, which fits u64");
            lo.max(b.saturating_sub(delta))
        }
        Ordering::Equal => b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_satisfy_genesis_validation() {
        // MAX_GAS_r = 2·TARGET_GAS_r for both resources.
        assert_eq!(MAX_GAS_EXEC, 2 * TARGET_GAS_EXEC);
        assert_eq!(MAX_GAS_STOR, 2 * TARGET_GAS_STOR);
        // MAX_GAS_r · BASE_FEE_r_MAX fits u64 for both resources.
        assert_eq!(BASE_FEE_EXEC_MAX, u64::MAX / MAX_GAS_EXEC);
        assert_eq!(BASE_FEE_STOR_MAX, u64::MAX / MAX_GAS_STOR);
        assert!(MAX_GAS_EXEC.checked_mul(BASE_FEE_EXEC_MAX).is_some());
        assert!(MAX_GAS_STOR.checked_mul(BASE_FEE_STOR_MAX).is_some());
        // Spec parameter values, pinned.
        assert_eq!(BASE_FEE_EXEC_MAX, 1_844_674_407_370);
        assert_eq!(BASE_FEE_STOR_MAX, 18_446_744_073_709);
    }

    #[test]
    fn at_target_price_is_unchanged() {
        assert_eq!(
            next_base_fee(
                100,
                TARGET_GAS_EXEC,
                TARGET_GAS_EXEC,
                8,
                8,
                BASE_FEE_EXEC_MAX
            ),
            100
        );
    }

    #[test]
    fn live_upward_from_the_minimum() {
        // One unit above target must move the price up by at least 1, even at
        // b = 8 where the proportional delta rounds to 0.
        let next = next_base_fee(
            8,
            TARGET_GAS_EXEC + 1,
            TARGET_GAS_EXEC,
            8,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(next, 9);
    }

    #[test]
    fn full_deviation_moves_exactly_one_eighth() {
        // g = 2T clamps deviation to T: delta = b/8 exactly (±12.5%).
        let b = 8_000;
        let up = next_base_fee(
            b,
            2 * TARGET_GAS_EXEC,
            TARGET_GAS_EXEC,
            8,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(up, b + b / 8);
        let down = next_base_fee(b, 0, TARGET_GAS_EXEC, 8, 8, BASE_FEE_EXEC_MAX);
        assert_eq!(down, b - b / 8);
    }

    #[test]
    fn deviation_clamp_bounds_any_overshoot() {
        // Usage far above 2T moves no further than the full-deviation step.
        let b = 8_000;
        let extreme = next_base_fee(b, u64::MAX, TARGET_GAS_EXEC, 8, 8, BASE_FEE_EXEC_MAX);
        assert_eq!(extreme, b + b / 8);
    }

    #[test]
    fn asymmetric_at_small_prices() {
        // One unit below target rounds the down-delta to zero: price holds.
        let next = next_base_fee(
            100,
            TARGET_GAS_EXEC - 1,
            TARGET_GAS_EXEC,
            8,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(next, 100);
    }

    #[test]
    fn saturates_at_bounds() {
        // Down-step clamps at lo.
        assert_eq!(
            next_base_fee(8, 0, TARGET_GAS_EXEC, 8, 8, BASE_FEE_EXEC_MAX),
            8
        );
        // Up-step clamps at hi, computed with a 128-bit product (b·deviation
        // would overflow u64 here).
        let at_cap = next_base_fee(
            BASE_FEE_EXEC_MAX,
            2 * TARGET_GAS_EXEC,
            TARGET_GAS_EXEC,
            8,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(at_cap, BASE_FEE_EXEC_MAX);
    }

    #[test]
    fn bounded_adjustment_over_a_grid() {
        // |next − b| ≤ max(1, b/8) and next ∈ [lo, hi], across a price × usage
        // grid including both extremes.
        let prices = [
            8,
            9,
            63,
            64,
            1_000,
            5_000_000,
            BASE_FEE_EXEC_MAX - 1,
            BASE_FEE_EXEC_MAX,
        ];
        let usages = [
            0,
            1,
            TARGET_GAS_EXEC - 1,
            TARGET_GAS_EXEC,
            TARGET_GAS_EXEC + 1,
            2 * TARGET_GAS_EXEC,
            u64::MAX,
        ];
        for b in prices {
            for g in usages {
                let next = next_base_fee(b, g, TARGET_GAS_EXEC, 8, 8, BASE_FEE_EXEC_MAX);
                let bound = 1.max(b / 8);
                assert!(
                    next.abs_diff(b) <= bound,
                    "move too large: b={b} g={g} next={next}"
                );
                assert!(
                    (8..=BASE_FEE_EXEC_MAX).contains(&next),
                    "out of range: b={b} g={g}"
                );
            }
        }
    }
}
