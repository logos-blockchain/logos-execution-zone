//! Fee assessment (SPECS.md §Fee assessment): `gas_stor`, `fee_reserve`, and
//! `fee_actual_base` over [`FeeTxView`].
//!
//! `FeeTxView` is `fee_core`'s own transaction abstraction; it does not
//! reference `LeeTransaction`. Later tasks convert.

use crate::{
    params::{PRIVATE_GAS_STOR, PRIVATE_VERIFY_GAS},
    state::FeeState,
};

/// Opaque payer/account identifier.
///
/// Deliberately shaped like `AccountId` (ledger spec) so conversion at the
/// call site is a straight copy, without `fee_core` depending on the ledger
/// crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayerId(pub [u8; 32]);

/// Fee-relevant view of a transaction (SPECS.md §Transactions).
///
/// System transactions (clock, deposit mints, cross-zone, genesis) never
/// reach `fee_core`: block-level code (T8) filters them out before
/// assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeTxView {
    /// A publicly executed transaction.
    Public {
        payer: PayerId,
        /// Execution bound; metering halts here.
        gas_limit: u64,
        /// Canonical serialized length.
        data_bytes: u64,
        /// Priority payment, MAY be 0.
        tip: u64,
        /// Signed cap on `fee_reserve`.
        max_fee: u128,
    },
    /// A privately verified transaction. All public fee fields are absent by
    /// construction (SPECS §Fee-validity private rule); gas quantities are
    /// protocol constants (`PRIVATE_VERIFY_GAS`, `PRIVATE_GAS_STOR`).
    Private { payer: PayerId },
}

impl FeeTxView {
    /// The transaction's payer.
    #[must_use]
    pub const fn payer(&self) -> PayerId {
        match self {
            Self::Public { payer, .. } | Self::Private { payer } => *payer,
        }
    }
}

/// Storage gas, known before execution.
#[must_use]
pub const fn gas_stor(tx: &FeeTxView) -> u64 {
    match tx {
        FeeTxView::Private { .. } => PRIVATE_GAS_STOR,
        FeeTxView::Public { data_bytes, .. } => *data_bytes,
    }
}

/// Amount held from the payer before execution, at the block's opening base
/// fees.
///
/// Only the execution part is uncertain in advance, so the reserve prices
/// `gas_limit` instead of `cycles`; for private transactions both gas
/// quantities are constants, so the reserve equals the eventual actual fee.
#[must_use]
pub fn fee_reserve(tx: &FeeTxView, state: &FeeState) -> u128 {
    match tx {
        FeeTxView::Private { .. } => wadd(
            wmul(PRIVATE_VERIFY_GAS, state.base_fee_exec),
            wmul(PRIVATE_GAS_STOR, state.base_fee_stor),
        ),
        FeeTxView::Public {
            gas_limit,
            data_bytes,
            tip,
            ..
        } => wadd(
            wadd(
                wmul(*gas_limit, state.base_fee_exec),
                wmul(*data_bytes, state.base_fee_stor),
            ),
            u128::from(*tip),
        ),
    }
}

/// Actual base fee, known once `cycles` are metered (public) or fixed at
/// `PRIVATE_VERIFY_GAS` (private; the caller supplies it, `fee_core` does
/// not execute anything).
///
/// Excludes the tip; see `fee_total = fee_base + tip`.
#[must_use]
pub fn fee_actual_base(cycles: u64, tx: &FeeTxView, state: &FeeState) -> u128 {
    wadd(
        wmul(cycles, state.base_fee_exec),
        wmul(gas_stor(tx), state.base_fee_stor),
    )
}

/// `a * b`, widened to `u128`; any `u64 * u64` fits `u128` by construction
/// (the widest product, `u64::MAX * u64::MAX`, is still less than
/// `u128::MAX`).
fn wmul(a: u64, b: u64) -> u128 {
    u128::from(a)
        .checked_mul(u128::from(b))
        .expect("u64 * u64 widened to u128 cannot overflow")
}

/// `a + b` in `u128`, checked.
const fn wadd(a: u128, b: u128) -> u128 {
    match a.checked_add(b) {
        Some(v) => v,
        None => panic!("sum overflow: protocol caps make this fit for any protocol-valid state"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "test code, plain arithmetic is clearer"
    )]

    use super::*;
    use crate::state::FeeState;

    const PAYER: PayerId = PayerId([1_u8; 32]);

    #[test]
    fn gas_stor_matches_kind() {
        let public = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 60_000,
            data_bytes: 200,
            tip: 100,
            max_fee: 10_u128.pow(9),
        };
        let private = FeeTxView::Private { payer: PAYER };
        assert_eq!(gas_stor(&public), 200);
        assert_eq!(gas_stor(&private), PRIVATE_GAS_STOR);
    }

    /// SPECS §Overview worked example, at genesis fees: a 50,000-cycle,
    /// 200-byte public tx pays 401,600; any private tx pays 5,070,616.
    #[test]
    fn worked_example_from_overview() {
        let state = FeeState::genesis().unwrap();
        let public = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 50_000,
            data_bytes: 200,
            tip: 0,
            max_fee: u128::MAX,
        };
        let public_fee = fee_actual_base(50_000, &public, &state);
        assert_eq!(public_fee, 401_600);

        let private = FeeTxView::Private { payer: PAYER };
        let private_fee = fee_actual_base(PRIVATE_VERIFY_GAS, &private, &state);
        assert_eq!(private_fee, 5_070_616);
        // fee_reserve equals the actual fee for private txs (constants only).
        assert_eq!(fee_reserve(&private, &state), private_fee);
    }

    /// SPECS.md Annex A "Usage" example: `fee_reserve` prices `gas_limit`
    /// (60,000), not the metered `cycles` (50,000) that
    /// `fee_actual_base` prices — the two differ whenever a transaction
    /// doesn't use its full gas limit, and the difference is the amount
    /// released back to the payer after settlement (SPECS §Overview
    /// "Reserve, execute, settle").
    #[test]
    fn public_fee_reserve_prices_gas_limit_not_metered_cycles() {
        let state = FeeState::genesis().unwrap();
        let tx = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 60_000,
            data_bytes: 200,
            tip: 100,
            max_fee: u128::MAX,
        };

        let reserve = fee_reserve(&tx, &state);
        assert_eq!(reserve, 60_000 * 8 + 200 * 8 + 100);

        let actual_base = fee_actual_base(50_000, &tx, &state);
        assert_eq!(actual_base, 401_600);

        // gas_limit (60_000) != cycles (50_000), so the reserve must exceed
        // the actual fee, and by exactly the unused gas priced at
        // base_fee_exec.
        assert!(reserve > actual_base + 100);
        assert_eq!(reserve - (actual_base + 100), (60_000 - 50_000) * 8);
    }
}
