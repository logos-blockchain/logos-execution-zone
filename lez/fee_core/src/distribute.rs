//! Revenue distribution (SPECS.md §Revenue distribution).
//!
//! A block's settled base revenue is credited to escrow and pushed into the
//! 50-slot window; the payout is the window average with the division
//! remainder carried forward, so every unit collected is eventually paid.

use crate::{
    error::{ConsensusFaultError, FeeError},
    params::SMOOTHING_WINDOW,
    state::FeeState,
};

/// Credits `revenue_base` to `escrow` and pushes it into `window`.
///
/// Evicts the oldest of `window`'s `SMOOTHING_WINDOW` slots (step 1 of
/// §Revenue distribution). Call once per block, before [`settle_payout`].
pub fn record_revenue(state: &mut FeeState, revenue_base: u128) {
    state.escrow = state
        .escrow
        .checked_add(revenue_base)
        .expect("escrow overflow: protocol caps make this fit for any protocol-valid state");
    let idx = usize::from(state.cursor);
    state.window[idx] = revenue_base;
    let next = idx
        .checked_add(1)
        .expect("idx < SMOOTHING_WINDOW (50), always fits");
    state.cursor = if next == state.window.len() {
        0
    } else {
        u8::try_from(next).expect("next <= SMOOTHING_WINDOW (50), always fits u8")
    };
}

/// Computes this block's payout as the window average plus carried
/// remainder.
///
/// Updates `payout_carry`, and debits `escrow` (step 2 of §Revenue
/// distribution). Returns the payout; the caller credits the producer with
/// `payout + revenue_tip` (`fee_core` does not touch balances).
///
/// # Errors
///
/// Returns [`FeeError::ConsensusFault`] if `payout > escrow`. This is an
/// invariant (SPECS §Invariants #4) that holds by construction for any
/// state reachable from genesis through this module's functions; a
/// violation means state was corrupted some other way and the caller MUST
/// halt rather than clamp the payout.
pub fn settle_payout(state: &mut FeeState) -> Result<u128, FeeError> {
    let window_sum: u128 = state
        .window
        .iter()
        .try_fold(0_u128, |acc, &v| acc.checked_add(v))
        .expect("window sum overflow: protocol caps make this fit for any protocol-valid state");
    let numerator = window_sum
        .checked_add(state.payout_carry)
        .expect("numerator overflow: protocol caps make this fit for any protocol-valid state");
    let window = u128::try_from(SMOOTHING_WINDOW).expect("SMOOTHING_WINDOW (50) fits u128");
    let payout = numerator
        .checked_div(window)
        .expect("SMOOTHING_WINDOW is nonzero");
    state.payout_carry = numerator
        .checked_rem(window)
        .expect("SMOOTHING_WINDOW is nonzero");
    if payout > state.escrow {
        return Err(FeeError::ConsensusFault(
            ConsensusFaultError::PayoutExceedsEscrow {
                payout,
                escrow: state.escrow,
            },
        ));
    }
    state.escrow = state
        .escrow
        .checked_sub(payout)
        .expect("payout <= escrow, checked above");
    Ok(payout)
}

/// Full per-block distribution step.
///
/// Records `revenue_base` then settles the payout (SPECS.md §Revenue
/// distribution, §Block transition step 3). Convenience wrapper over
/// [`record_revenue`] + [`settle_payout`] in the order the protocol
/// requires.
///
/// # Errors
///
/// See [`settle_payout`].
pub fn distribute(state: &mut FeeState, revenue_base: u128) -> Result<u128, FeeError> {
    record_revenue(state, revenue_base);
    settle_payout(state)
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
    use crate::error::{ConsensusFaultError, FeeError};

    #[test]
    fn first_block_below_window_width_pays_zero_and_carries_the_rest() {
        // Revenue under SMOOTHING_WINDOW floor-divides to a zero payout; the
        // whole amount is carried forward, none lost.
        let mut state = FeeState::genesis().unwrap();
        let payout = distribute(&mut state, 30).unwrap();
        assert_eq!(payout, 0);
        assert_eq!(state.payout_carry, 30);
        assert_eq!(state.escrow, 30);
    }

    #[test]
    fn revenue_evenly_divisible_by_window_pays_out_immediately() {
        let mut state = FeeState::genesis().unwrap();
        let payout = distribute(&mut state, 100).unwrap();
        assert_eq!(payout, 2);
        assert_eq!(state.payout_carry, 0);
        assert_eq!(state.escrow, 98);
    }

    #[test]
    fn window_wraps_after_smoothing_window_blocks() {
        let mut state = FeeState::genesis().unwrap();
        for _ in 0..SMOOTHING_WINDOW {
            distribute(&mut state, 50).unwrap();
        }
        assert_eq!(state.cursor, 0);
        assert_eq!(state.window, [50_u128; SMOOTHING_WINDOW]);
    }

    #[test]
    fn cumulative_payout_never_exceeds_cumulative_revenue() {
        let mut state = FeeState::genesis().unwrap();
        let mut total_revenue: u128 = 0;
        let mut total_payout: u128 = 0;
        for i in 0..200_u128 {
            let revenue = (i * 37) % 1_000;
            total_revenue += revenue;
            total_payout += distribute(&mut state, revenue).unwrap();
            assert!(total_payout <= total_revenue);
            assert!(state.payout_carry < u128::try_from(SMOOTHING_WINDOW).unwrap());
        }
    }

    #[test]
    fn every_unit_is_eventually_paid_once_window_drains() {
        // A single revenue pulse, then SMOOTHING_WINDOW blocks of zero
        // revenue: the escrow must reach exactly zero once the window has
        // fully drained (exact amortization, SPECS §Revenue distribution).
        let mut state = FeeState::genesis().unwrap();
        distribute(&mut state, 1_000).unwrap();
        for _ in 0..SMOOTHING_WINDOW - 1 {
            distribute(&mut state, 0).unwrap();
        }
        assert_eq!(state.escrow, 0);
        assert_eq!(state.payout_carry, 0);
    }

    #[test]
    fn payout_exceeding_escrow_is_a_consensus_fault() {
        // Construct an impossible state directly (escrow forced to 0 while
        // the window holds revenue) to exercise the guard.
        let mut state = FeeState::genesis().unwrap();
        state.window[0] = 1_000;
        state.escrow = 0;
        let err = settle_payout(&mut state).unwrap_err();
        assert!(matches!(
            err,
            FeeError::ConsensusFault(ConsensusFaultError::PayoutExceedsEscrow { .. })
        ));
    }
}
