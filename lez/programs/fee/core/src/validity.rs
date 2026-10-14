//! Static fee-validity rules and the checked block gas-cap accumulators.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "spec-mandated integer math: accumulator sums are widened to u128 before the \
              checked cap comparison"
)]

use thiserror::Error;

use crate::{
    assess::{FeeTxView, fee_reserve, private_fee_required},
    market,
    state::FeeState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FeeError {
    #[error("data_bytes {data_bytes} outside 1..=max {}", market::MAX_GAS_STOR)]
    DataBytesOutOfRange { data_bytes: u64 },

    #[error("gas_limit {gas_limit} above max {}", market::MAX_GAS_EXEC)]
    GasLimitAboveCap { gas_limit: u64 },

    #[error("max_fee {max_fee} below the fee reserve {fee_reserve}")]
    MaxFeeBelowReserve { fee_reserve: u128, max_fee: u128 },

    #[error("fee height {fee_height} outside the window ending at {height}")]
    FeeHeightOutOfWindow { fee_height: u64, height: u64 },

    #[error("private fee {paid} below the required {required}")]
    PrivateFeeBelowRequired { required: u128, paid: u128 },

    #[error(
        "block execution gas total {total} exceeds max {}",
        market::MAX_GAS_EXEC
    )]
    ExecGasCapExceeded { total: u128 },

    #[error("block storage gas total {total} exceeds max {}", market::MAX_GAS_STOR)]
    StorGasCapExceeded { total: u128 },
}

/// Static fee-validity (spec *Fee-validity*), checked before execution at the
/// block's opening fee state.
pub fn validate_static_tx(view: &FeeTxView, fee_state: &FeeState) -> Result<(), FeeError> {
    match view {
        FeeTxView::Public {
            gas_limit,
            data_bytes,
            max_fee,
            ..
        } => {
            if *data_bytes == 0 || *data_bytes > market::MAX_GAS_STOR {
                return Err(FeeError::DataBytesOutOfRange {
                    data_bytes: *data_bytes,
                });
            }
            if *gas_limit > market::MAX_GAS_EXEC {
                return Err(FeeError::GasLimitAboveCap {
                    gas_limit: *gas_limit,
                });
            }
            let reserve = fee_reserve(view, fee_state);
            if reserve > *max_fee {
                return Err(FeeError::MaxFeeBelowReserve {
                    fee_reserve: reserve,
                    max_fee: *max_fee,
                });
            }
            Ok(())
        }
        // The flat part only: metered effects are priced after execution.
        FeeTxView::Private { paid, fee_height } => {
            let (base_fee_exec, base_fee_stor) =
                fee_state
                    .base_fees_at(*fee_height)
                    .ok_or(FeeError::FeeHeightOutOfWindow {
                        fee_height: *fee_height,
                        height: fee_state.height,
                    })?;
            let required = private_fee_required(0, base_fee_exec, base_fee_stor);
            if *paid < required {
                return Err(FeeError::PrivateFeeBelowRequired {
                    required,
                    paid: *paid,
                });
            }
            Ok(())
        }
    }
}

/// Adds one transaction's metered cycles to the block's execution total,
/// widened and checked against the cap (spec: totals are checked, never
/// wrapped).
pub fn accumulate_exec_gas(total: u64, cycles: u64) -> Result<u64, FeeError> {
    let widened = u128::from(total) + u128::from(cycles);
    if widened > u128::from(market::MAX_GAS_EXEC) {
        return Err(FeeError::ExecGasCapExceeded { total: widened });
    }
    Ok(u64::try_from(widened).expect("bounded by MAX_GAS_EXEC"))
}

/// Adds one transaction's storage bytes to the block's storage total, widened
/// and checked against the cap.
pub fn accumulate_stor_gas(total: u64, bytes: u64) -> Result<u64, FeeError> {
    let widened = u128::from(total) + u128::from(bytes);
    if widened > u128::from(market::MAX_GAS_STOR) {
        return Err(FeeError::StorGasCapExceeded { total: widened });
    }
    Ok(u64::try_from(widened).expect("bounded by MAX_GAS_STOR"))
}

#[cfg(test)]
mod tests {
    use lee_core::account::AccountId;

    use super::*;

    fn public_view(gas_limit: u64, data_bytes: u64, max_fee: u128) -> FeeTxView {
        FeeTxView::Public {
            payer: AccountId::new([7_u8; 32]),
            gas_limit,
            data_bytes,
            tip: 0,
            max_fee,
        }
    }

    #[test]
    fn static_rules_accept_a_plain_transaction() {
        let view = public_view(50_000, 200, u128::MAX);
        assert_eq!(validate_static_tx(&view, &FeeState::genesis()), Ok(()));
    }

    #[test]
    fn zero_and_oversized_data_bytes_are_rejected() {
        let state = FeeState::genesis();
        assert!(matches!(
            validate_static_tx(&public_view(0, 0, u128::MAX), &state),
            Err(FeeError::DataBytesOutOfRange { data_bytes: 0 })
        ));
        assert!(matches!(
            validate_static_tx(&public_view(0, market::MAX_GAS_STOR + 1, u128::MAX), &state),
            Err(FeeError::DataBytesOutOfRange { .. })
        ));
    }

    #[test]
    fn gas_limit_above_the_cap_is_rejected() {
        assert!(matches!(
            validate_static_tx(
                &public_view(market::MAX_GAS_EXEC + 1, 1, u128::MAX),
                &FeeState::genesis()
            ),
            Err(FeeError::GasLimitAboveCap { .. })
        ));
    }

    #[test]
    fn max_fee_boundary_is_exact() {
        let state = FeeState::genesis();
        let view = public_view(50_000, 200, 0);
        let reserve = fee_reserve(&view, &state);
        assert_eq!(
            validate_static_tx(&public_view(50_000, 200, reserve), &state),
            Ok(()),
            "max_fee equal to the reserve is valid",
        );
        assert!(matches!(
            validate_static_tx(&public_view(50_000, 200, reserve - 1), &state),
            Err(FeeError::MaxFeeBelowReserve { .. })
        ));
    }

    #[test]
    fn private_view_needs_a_height_in_the_window_and_the_flat_fee() {
        let mut state = FeeState::genesis();
        for _ in 0..=market::PRIVATE_FEE_WINDOW {
            state.apply_block(&crate::BlockFeeSummary::default());
        }
        let flat = private_fee_required(0, state.base_fee_exec, state.base_fee_stor);
        let view = |paid, fee_height| FeeTxView::Private { paid, fee_height };

        assert_eq!(
            validate_static_tx(&view(flat, state.height), &state),
            Ok(())
        );
        assert_eq!(validate_static_tx(&view(flat, 1), &state), Ok(()));
        assert!(matches!(
            validate_static_tx(&view(flat, 0), &state),
            Err(FeeError::FeeHeightOutOfWindow { .. })
        ));
        assert!(matches!(
            validate_static_tx(&view(flat, state.height + 1), &state),
            Err(FeeError::FeeHeightOutOfWindow { .. })
        ));
        assert!(matches!(
            validate_static_tx(&view(flat - 1, state.height), &state),
            Err(FeeError::PrivateFeeBelowRequired { .. })
        ));
    }

    #[test]
    fn cap_accumulators_are_exact_and_checked() {
        assert_eq!(
            accumulate_exec_gas(market::MAX_GAS_EXEC - 1, 1),
            Ok(market::MAX_GAS_EXEC),
            "reaching the cap exactly is allowed",
        );
        assert!(matches!(
            accumulate_exec_gas(market::MAX_GAS_EXEC, 1),
            Err(FeeError::ExecGasCapExceeded { .. })
        ));
        assert_eq!(
            accumulate_stor_gas(market::MAX_GAS_STOR - 1, 1),
            Ok(market::MAX_GAS_STOR)
        );
        assert!(matches!(
            accumulate_stor_gas(market::MAX_GAS_STOR, 1),
            Err(FeeError::StorGasCapExceeded { .. })
        ));
        // Widened accumulation cannot wrap even with absurd inputs.
        assert!(matches!(
            accumulate_exec_gas(u64::MAX, u64::MAX),
            Err(FeeError::ExecGasCapExceeded { .. })
        ));
    }
}
