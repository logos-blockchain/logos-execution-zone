//! The dual fee market: protocol constants and the base-fee controller.
//!
//! All values are protocol constants; changing any is a protocol-version
//! change.

use core::cmp::Ordering;

use crate::Fee;

pub const TARGET_GAS_EXEC: u64 = 5_000_000;
pub const MAX_GAS_EXEC: u64 = 10_000_000;
pub const D_EXEC: u64 = 8;
pub const BASE_FEE_EXEC_MIN: Fee = 8;
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "cap is floor(u64::MAX / MAX_GAS_EXEC) so MAX_GAS·price fits u64"
)]
pub const BASE_FEE_EXEC_MAX: Fee = u64::MAX / MAX_GAS_EXEC;

pub const TARGET_GAS_STOR: u64 = 500_000;
pub const MAX_GAS_STOR: u64 = 1_000_000;
pub const D_STOR: u64 = 8;
pub const BASE_FEE_STOR_MIN: Fee = 8;
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "cap is floor(u64::MAX / MAX_GAS_STOR) so MAX_GAS·price fits u64"
)]
pub const BASE_FEE_STOR_MAX: Fee = u64::MAX / MAX_GAS_STOR;

pub const SMOOTHING_WINDOW: usize = 50;

// Genesis validation: the ±12.5% bound and elasticity framing assume
// MAX = 2·TARGET for both resources.
const _: () = assert!(MAX_GAS_EXEC == 2 * TARGET_GAS_EXEC);
const _: () = assert!(MAX_GAS_STOR == 2 * TARGET_GAS_STOR);

/// One base-fee update.
///
/// The deviation clamp bounds the move to `max(1, base_fee / damping)`. Products
/// are widened to u128 to keep the function total over any u64 input; under the
/// `base_fee <= BASE_FEE_*_MAX` invariant the u64 products already fit
/// (`base_fee * deviation <= u64::MAX / 2`), so the widening is robustness, not
/// overflow avoidance. A moving branch saturates into `[lo, hi]`; at target
/// `base_fee` is returned unchanged (callers keep `base_fee` within `[lo, hi]`).
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "spec-mandated integer math: products are widened to u128 and subtractions are \
              guarded by the enclosing comparison"
)]
#[must_use]
pub fn next_base_fee(
    base_fee: Fee,
    gas_used: u64,
    target: u64,
    damping: u64,
    lo: Fee,
    hi: Fee,
) -> Fee {
    match gas_used.cmp(&target) {
        Ordering::Greater => {
            let deviation = (gas_used - target).min(target);
            let delta = ((u128::from(base_fee) * u128::from(deviation))
                / (u128::from(target) * u128::from(damping)))
            .max(1);
            let delta =
                u64::try_from(delta).expect("delta is at most base_fee/damping, which fits u64");
            hi.min(base_fee.saturating_add(delta))
        }
        Ordering::Less => {
            let deviation = (target - gas_used).min(target);
            let delta = (u128::from(base_fee) * u128::from(deviation))
                / (u128::from(target) * u128::from(damping));
            let delta =
                u64::try_from(delta).expect("delta is at most base_fee/damping, which fits u64");
            lo.max(base_fee.saturating_sub(delta))
        }
        Ordering::Equal => base_fee,
    }
}

#[cfg(test)]
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "test arithmetic on small literal values"
)]
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
        // base_fee = 8 where the proportional delta rounds to 0.
        let base_fee = 8;
        let next = next_base_fee(
            base_fee,
            TARGET_GAS_EXEC + 1,
            TARGET_GAS_EXEC,
            8,
            8,
            BASE_FEE_EXEC_MAX,
        );
        assert_eq!(next, base_fee + 1);
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
        // Up-step clamps at hi. At the cap `b·deviation` is ≈ u64::MAX / 2 — it
        // fits u64 by construction; the u128 product is for totality, not need.
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
