//! Fee assessment: the reserve and actual-fee formulas.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "spec-mandated integer math: every product is widened to u128 and every sum is \
              checked against caps that keep the terms in u64"
)]

use lee_core::account::AccountId;

use crate::{market, state::FeeState};

/// The fee-relevant view of a transaction (spec *Transactions*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeTxView {
    Public {
        payer: AccountId,
        gas_limit: u64,
        data_bytes: u64,
        tip: u64,
        max_fee: u128,
    },
    Private {
        payer: AccountId,
    },
}

impl FeeTxView {
    #[must_use]
    pub const fn payer(&self) -> AccountId {
        match self {
            Self::Public { payer, .. } | Self::Private { payer } => *payer,
        }
    }

    /// Storage gas: serialized bytes for public, the canonical constant size
    /// for private.
    #[must_use]
    pub const fn gas_stor(&self) -> u64 {
        match self {
            Self::Public { data_bytes, .. } => *data_bytes,
            Self::Private { .. } => market::PRIVATE_GAS_STOR,
        }
    }

    /// The execution gas the reserve prices: the signed limit for public, the
    /// fixed verification cost for private (which makes the private reserve
    /// equal the private actual fee).
    #[must_use]
    pub const fn gas_limit(&self) -> u64 {
        match self {
            Self::Public { gas_limit, .. } => *gas_limit,
            Self::Private { .. } => market::PRIVATE_VERIFY_GAS,
        }
    }

    #[must_use]
    pub const fn tip(&self) -> u64 {
        match self {
            Self::Public { tip, .. } => *tip,
            Self::Private { .. } => 0,
        }
    }
}

/// The amount held from the payer before execution, at the block's opening
/// base fees: `gas_limit·base_fee_exec + gas_stor·base_fee_stor + tip`.
///
/// The caller must pass a cap-validated view (gas within `MAX_GAS_*`) and a
/// well-formed `FeeState` whose base fees stay in `[MIN, BASE_FEE_*_MAX]` — the
/// bounds `next_base_fee` maintains. Under those preconditions every product
/// fits u64 and the u128 sum cannot overflow; on an unchecked view against a
/// corrupt state it could wrap silently in release.
#[must_use]
pub fn fee_reserve(view: &FeeTxView, fee_state: &FeeState) -> u128 {
    u128::from(view.gas_limit()) * u128::from(fee_state.base_fee_exec)
        + u128::from(view.gas_stor()) * u128::from(fee_state.base_fee_stor)
        + u128::from(view.tip())
}

/// The base fee actually owed after execution.
///
/// `gas_exec·base_fee_exec + gas_stor·base_fee_stor`, where `gas_exec` is the
/// executed cycle count clamped to the transaction's `gas_limit` for public
/// transactions (a session may overshoot its budget by up to one instruction,
/// but a transaction is never billed past the gas it declared) and the fixed
/// verification cost for private. Clamping here keeps `actual + tip ≤ reserve`
/// regardless of what the caller passes.
#[must_use]
pub fn fee_actual_base(charged_cycles: u64, view: &FeeTxView, fee_state: &FeeState) -> u128 {
    let gas_exec = match view {
        FeeTxView::Public { gas_limit, .. } => charged_cycles.min(*gas_limit),
        FeeTxView::Private { .. } => market::PRIVATE_VERIFY_GAS,
    };
    u128::from(gas_exec) * u128::from(fee_state.base_fee_exec)
        + u128::from(view.gas_stor()) * u128::from(fee_state.base_fee_stor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::market;

    fn genesis() -> FeeState {
        FeeState::genesis()
    }

    fn payer() -> AccountId {
        AccountId::new([7_u8; 32])
    }

    #[test]
    fn spec_worked_example_public() {
        // At genesis both base fees are 8: a 50,000-cycle transaction carrying
        // 200 bytes pays 50,000·8 + 200·8 = 401,600.
        let view = FeeTxView::Public {
            payer: payer(),
            gas_limit: 50_000,
            data_bytes: 200,
            tip: 0,
            max_fee: u128::MAX,
        };
        assert_eq!(fee_reserve(&view, &genesis()), 401_600);
        assert_eq!(fee_actual_base(50_000, &view, &genesis()), 401_600);
    }

    #[test]
    fn spec_worked_example_private() {
        // Any private transaction pays 409,764·8 + 224,063·8 = 5,070,616,
        // identical for all of them in that block, and its reserve equals its
        // actual fee.
        let view = FeeTxView::Private { payer: payer() };
        assert_eq!(fee_reserve(&view, &genesis()), 5_070_616);
        assert_eq!(fee_actual_base(0, &view, &genesis()), 5_070_616);
        assert_eq!(
            fee_reserve(&view, &genesis()),
            fee_actual_base(u64::MAX, &view, &genesis()),
            "private reserve equals private actual regardless of reported cycles",
        );
    }

    #[test]
    fn reserve_dominates_actual_even_past_the_limit() {
        let view = FeeTxView::Public {
            payer: payer(),
            gas_limit: 10_000,
            data_bytes: 100,
            tip: 5,
            max_fee: u128::MAX,
        };
        let state = genesis();
        let reserve = fee_reserve(&view, &state);
        // Including cycle counts above the limit: the clamp keeps the actual fee
        // bounded by the reserve, so the payer is never billed past gas_limit.
        for cycles in [0, 1, 5_000, 10_000, 10_001, 1_000_000, u64::MAX] {
            assert!(fee_actual_base(cycles, &view, &state) + u128::from(view.tip()) <= reserve);
        }
    }

    #[test]
    fn products_cannot_overflow_at_the_caps() {
        // Invariant 5 sizing: MAX_GAS·BASE_FEE_MAX fits u64 per resource, so
        // the u128 sums are far from overflow even at the extremes.
        let mut state = genesis();
        state.base_fee_exec = market::BASE_FEE_EXEC_MAX;
        state.base_fee_stor = market::BASE_FEE_STOR_MAX;
        let view = FeeTxView::Public {
            payer: payer(),
            gas_limit: market::MAX_GAS_EXEC,
            data_bytes: market::MAX_GAS_STOR,
            tip: u64::MAX,
            max_fee: u128::MAX,
        };
        let reserve = fee_reserve(&view, &state);
        assert!(reserve > 0);
        assert!(fee_actual_base(market::MAX_GAS_EXEC, &view, &state) < reserve);
    }
}
