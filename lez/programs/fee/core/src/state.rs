//! Persistent fee market state, stored in the fee-state account's data.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "spec-mandated integer math: the payout split is floor division with an explicit \
              carry, and additions are checked"
)]

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{BlockFeeSummary, market};

/// The fee market's persistent state, Borsh-serialized into the fee-state
/// account's `data`. The escrow is the escrow *account balance*, deliberately
/// not a field here.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeState {
    /// Execution base fee for the current block.
    pub base_fee_exec: u64,
    /// Storage base fee for the current block.
    pub base_fee_stor: u64,
    /// Base revenue of the last [`market::SMOOTHING_WINDOW`] blocks; slot
    /// `height % SMOOTHING_WINDOW` is the most recent.
    pub window: [u128; market::SMOOTHING_WINDOW],
    /// Payout division remainder, always < [`market::SMOOTHING_WINDOW`].
    pub payout_carry: u128,
    /// Block height; an increment at 2^64 - 1 is a consensus fault.
    pub height: u64,
}

impl FeeState {
    /// The state every zone starts from: both base fees at their minimum,
    /// empty window, zero carry, height zero.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            base_fee_exec: market::BASE_FEE_EXEC_MIN,
            base_fee_stor: market::BASE_FEE_STOR_MIN,
            window: [0; market::SMOOTHING_WINDOW],
            payout_carry: 0,
            height: 0,
        }
    }

    /// Applies one block's summary: pushes the block's base revenue into the
    /// window, computes the smoothed payout and carry, updates both base fees,
    /// and advances the height. Returns the payout owed to the producer from
    /// escrow.
    pub fn apply_block(&mut self, summary: &BlockFeeSummary) -> u128 {
        self.height = self
            .height
            .checked_add(1)
            .expect("height increment at u64::MAX is a consensus fault");

        let window_len = u64::try_from(market::SMOOTHING_WINDOW).expect("window length fits u64");
        let slot = usize::try_from(self.height % window_len).expect("slot index fits usize");
        self.window[slot] = summary.revenue_base;

        let numerator = self.window.iter().fold(self.payout_carry, |acc, revenue| {
            acc.checked_add(*revenue)
                .expect("window sum of 50 u128 revenues cannot overflow in practice")
        });
        let window_len = u128::from(window_len);
        let payout = numerator / window_len;
        self.payout_carry = numerator % window_len;

        self.base_fee_exec = market::next_base_fee(
            self.base_fee_exec,
            summary.gas_used_exec,
            market::TARGET_GAS_EXEC,
            market::D_EXEC,
            market::BASE_FEE_EXEC_MIN,
            market::BASE_FEE_EXEC_MAX,
        );
        self.base_fee_stor = market::next_base_fee(
            self.base_fee_stor,
            summary.gas_used_stor,
            market::TARGET_GAS_STOR,
            market::D_STOR,
            market::BASE_FEE_STOR_MIN,
            market::BASE_FEE_STOR_MAX,
        );

        payout
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("FeeState serialization should not fail")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        borsh::from_slice(bytes).expect("FeeState deserialization should not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockFeeSummary;

    fn summary_with_revenue(revenue_base: u128) -> BlockFeeSummary {
        BlockFeeSummary {
            revenue_base,
            ..BlockFeeSummary::default()
        }
    }

    #[test]
    fn genesis_matches_spec() {
        let state = FeeState::genesis();
        assert_eq!(state.base_fee_exec, market::BASE_FEE_EXEC_MIN);
        assert_eq!(state.base_fee_stor, market::BASE_FEE_STOR_MIN);
        assert_eq!(state.window, [0; market::SMOOTHING_WINDOW]);
        assert_eq!(state.payout_carry, 0);
        assert_eq!(state.height, 0);
    }

    #[test]
    fn serialization_round_trips() {
        let mut state = FeeState::genesis();
        state.apply_block(&summary_with_revenue(12_345));
        assert_eq!(FeeState::from_bytes(&state.to_bytes()), state);
    }

    #[test]
    fn zero_load_holds_the_floor() {
        let mut state = FeeState::genesis();
        for expected_height in 1..=120_u64 {
            let payout = state.apply_block(&BlockFeeSummary::default());
            assert_eq!(payout, 0);
            assert_eq!(state.height, expected_height);
        }
        assert_eq!(state.base_fee_exec, market::BASE_FEE_EXEC_MIN);
        assert_eq!(state.base_fee_stor, market::BASE_FEE_STOR_MIN);
        assert_eq!(state.payout_carry, 0);
    }

    #[test]
    fn congested_blocks_raise_both_fees() {
        let mut state = FeeState::genesis();
        let full = BlockFeeSummary {
            gas_used_exec: market::MAX_GAS_EXEC,
            gas_used_stor: market::MAX_GAS_STOR,
            ..BlockFeeSummary::default()
        };
        state.apply_block(&full);
        // From the floor, one congested block moves each fee up by max(1, 8/8) = 1.
        assert_eq!(state.base_fee_exec, market::BASE_FEE_EXEC_MIN + 1);
        assert_eq!(state.base_fee_stor, market::BASE_FEE_STOR_MIN + 1);
    }

    #[test]
    fn revenue_pulse_amortizes_exactly_over_the_window() {
        // A pulse of R contributes to exactly 50 consecutive payouts starting
        // with the collecting block, and nothing is stranded. 1234567 is
        // deliberately not divisible by 50.
        const PULSE: u128 = 1_234_567;
        let mut state = FeeState::genesis();
        let mut paid = state.apply_block(&summary_with_revenue(PULSE));
        for _ in 0..market::SMOOTHING_WINDOW - 1 {
            paid += state.apply_block(&BlockFeeSummary::default());
        }
        assert_eq!(paid, PULSE, "the 50th payout completes the pulse");
        // After the window passes, nothing remains: payouts and carry are zero.
        assert_eq!(state.apply_block(&BlockFeeSummary::default()), 0);
        assert_eq!(state.payout_carry, 0);
    }

    #[test]
    fn carry_stays_below_the_window_length() {
        let mut state = FeeState::genesis();
        let window_len = u128::try_from(market::SMOOTHING_WINDOW).expect("fits u128");
        for i in 0..200_u128 {
            state.apply_block(&summary_with_revenue(i * 7 + 3));
            assert!(state.payout_carry < window_len);
        }
    }

    #[test]
    fn cumulative_payout_never_exceeds_cumulative_revenue() {
        // Payout ≤ escrow at every block, where escrow is cumulative revenue
        // minus cumulative payouts.
        let mut state = FeeState::genesis();
        let (mut revenue, mut paid): (u128, u128) = (0, 0);
        for i in 0..200_u128 {
            let r = (i * 31) % 97;
            revenue += r;
            paid += state.apply_block(&summary_with_revenue(r));
            assert!(paid <= revenue, "payout exceeded revenue at block {i}");
        }
    }
}
