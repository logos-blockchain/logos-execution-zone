//! Fee-validity (SPECS.md §Fee-validity).
//!
//! Static per-tx and per-block checks, plus the payer-authorization and
//! deployment-policy seams that are deliberately left open (D1/D2/D3; see
//! the `TBA(Qn)` markers).

use crate::{
    assess::{FeeTxView, PayerId, fee_reserve, gas_stor},
    error::{FeeError, InvalidBlockError},
    params::{MAX_GAS_EXEC, MAX_GAS_STOR},
    state::FeeState,
};

/// D2 seam: the fee treatment of program deployments.
// TBA(Q2): answered — deployments are folded into the public fee model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentFeePolicy {
    /// Deployments are priced exactly like public transactions: storage gas
    /// over the full serialized transaction (ELF included), execution gas over
    /// their metered cycles.
    ///
    /// Charging (recognizing a deployment and assessing it) is the block-level
    /// caller's job (T8); `fee_core` only exposes the knob.
    PricedAsPublic,
}

/// The deployment fee policy (tokenomics ruling Q2).
#[must_use]
pub const fn deployment_policy() -> DeploymentFeePolicy {
    DeploymentFeePolicy::PricedAsPublic
}

/// Static per-transaction fee-validity (SPECS §Fee-validity).
///
/// The private rule ("no public-only fields") holds structurally:
/// [`FeeTxView::Private`] has no such fields to check.
///
/// # Errors
///
/// Returns [`FeeError::InvalidBlock`] describing which condition failed.
pub fn validate_static_tx(tx: &FeeTxView, state: &FeeState) -> Result<(), FeeError> {
    let FeeTxView::Public {
        gas_limit,
        data_bytes,
        max_fee,
        ..
    } = tx
    else {
        return Ok(());
    };
    if *data_bytes < 1 {
        return Err(FeeError::InvalidBlock(InvalidBlockError::EmptyDataBytes));
    }
    if *data_bytes > MAX_GAS_STOR {
        return Err(FeeError::InvalidBlock(
            InvalidBlockError::DataBytesExceedsMax {
                data_bytes: *data_bytes,
                max: MAX_GAS_STOR,
            },
        ));
    }
    if *gas_limit > MAX_GAS_EXEC {
        return Err(FeeError::InvalidBlock(
            InvalidBlockError::GasLimitExceedsMax {
                gas_limit: *gas_limit,
                max: MAX_GAS_EXEC,
            },
        ));
    }
    let reserve = fee_reserve(tx, state);
    if reserve > *max_fee {
        return Err(FeeError::InvalidBlock(
            InvalidBlockError::FeeReserveExceedsMaxFee {
                fee_reserve: reserve,
                max_fee: *max_fee,
            },
        ));
    }
    Ok(())
}

/// Static block-level fee-validity.
///
/// Every transaction must be statically fee-valid, and the cumulative
/// storage total must stay within `MAX_GAS_STOR` (SPECS §Fee-validity). The
/// execution cap is dynamic and enforced by the caller as metered cycles
/// become known; see [`accumulate_gas_used`].
///
/// **Not yet consumed by the live protocol, and it does not agree with it.** The block transition
/// enforces the storage cap in `chain_state::apply::validate_block_storage_cap`, over every
/// non-system transaction's *real serialized wire size* — including private ones, which this
/// function would price at the `PRIVATE_GAS_STOR` constant instead (see [`gas_stor`]). It also
/// splits per-transaction static validity out to each transaction's turn, because whether a vault
/// claim is the fee-exempt full sweep depends on the vault balance at that point in the block.
/// Wiring this in unchanged would make the sequencer and the block transition disagree.
///
/// # Errors
///
/// Returns [`FeeError::InvalidBlock`] on the first failing transaction, or
/// if the cumulative storage total exceeds `MAX_GAS_STOR`.
// TBA(INCREMENTIAL): once the constant-size private wire format lands (T3/T5) and
// `PRIVATE_GAS_STOR` is re-pinned against it, the two rules coincide and this can become the
// shared implementation.
pub fn validate_static_block(txs: &[FeeTxView], state: &FeeState) -> Result<(), FeeError> {
    let mut total_stor: u128 = 0;
    for tx in txs {
        validate_static_tx(tx, state)?;
        total_stor = total_stor
            .checked_add(u128::from(gas_stor(tx)))
            .expect("cumulative storage total overflow: protocol caps make this fit for any protocol-valid state");
        if total_stor > u128::from(MAX_GAS_STOR) {
            return Err(FeeError::InvalidBlock(
                InvalidBlockError::StorageCapExceeded {
                    total: total_stor,
                    max: MAX_GAS_STOR,
                },
            ));
        }
    }
    Ok(())
}

/// Adds `amount` to `running_total` and checks the result against `cap`.
///
/// Uses checked `u64` addition so a wraparound can never mask an over-cap
/// total. Convenience for a caller's dynamic gas-cap enforcement (e.g.
/// `MAX_GAS_EXEC` as metered cycles become known, SPECS §Fee-validity);
/// `fee_core` does not execute transactions, so it cannot run that loop
/// itself.
///
/// # Errors
///
/// Returns [`FeeError::InvalidBlock`] if the addition overflows `u64` or the
/// new total exceeds `cap`.
pub fn accumulate_gas_used(running_total: u64, amount: u64, cap: u64) -> Result<u64, FeeError> {
    let total = running_total
        .checked_add(amount)
        .ok_or(FeeError::InvalidBlock(
            InvalidBlockError::GasAccumulationOverflow,
        ))?;
    if total > cap {
        return Err(FeeError::InvalidBlock(InvalidBlockError::GasCapExceeded {
            total,
            cap,
        }));
    }
    Ok(total)
}

/// D1 seam: authorizes a transaction's designated payer.
///
/// Q1 (answered): the payer is any account whose fee authorization accompanies
/// the transaction — an explicit designation plus a signature over the fee
/// fields and the exact transaction they cover. The payer MAY be one of the
/// transaction's signers and MAY be a third party outside the witness set
/// (sponsored transactions), and is never inferred from the witness set.
///
/// `fee_core` is pure arithmetic and cannot verify signatures, so the caller
/// supplies `authorized`: the account ids whose fee authorization verified at
/// the wire layer (`lee::fee_authorized_account_ids`). All this seam decides is
/// membership.
///
/// Called from `chain_state::check_charged_tx`, the one gate both the block
/// transition and the sequencer's block builder run a charged transaction
/// through.
///
/// # Errors
///
/// Returns `InvalidBlock(UnauthorizedPayer)` if `payer` is not one of
/// `authorized`.
// TBA(Q1-program-auth): the ruling also allows a program authorization; it
// enters through `authorized`, not through this function.
pub fn authorize_payer(payer: PayerId, authorized: &[PayerId]) -> Result<(), FeeError> {
    if authorized.contains(&payer) {
        Ok(())
    } else {
        Err(FeeError::InvalidBlock(InvalidBlockError::UnauthorizedPayer))
    }
}

/// D3 seam: authorizes a private transaction's payer against the tx's
/// public fee-authorized set.
///
/// A private transaction still names public signers for authorization; the
/// proof itself carries no public fee fields. Default rule: the payer must
/// be one of the publicly authorized accounts, and an empty set is
/// rejected, so fully-shielded transactions cannot pay fees until Q3 is
/// decided.
///
/// # Errors
///
/// Returns `InvalidBlock(EmptyPublicSignerSet)` if `public_authorized` is
/// empty, or `InvalidBlock(UnauthorizedPayer)` if `payer` is not among them.
// TBA(Q3)
pub fn authorize_private_payer(
    payer: PayerId,
    public_authorized: &[PayerId],
) -> Result<(), FeeError> {
    if public_authorized.is_empty() {
        return Err(FeeError::InvalidBlock(
            InvalidBlockError::EmptyPublicSignerSet,
        ));
    }
    authorize_payer(payer, public_authorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYER: PayerId = PayerId([1_u8; 32]);
    const OTHER: PayerId = PayerId([2_u8; 32]);

    fn genesis() -> FeeState {
        FeeState::genesis().unwrap()
    }

    #[test]
    fn public_tx_within_bounds_is_valid() {
        let state = genesis();
        let tx = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 60_000,
            data_bytes: 200,
            tip: 100,
            max_fee: 10_u128.pow(9),
        };
        assert!(validate_static_tx(&tx, &state).is_ok());
    }

    #[test]
    fn public_tx_with_zero_data_bytes_is_invalid() {
        let state = genesis();
        let tx = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 1,
            data_bytes: 0,
            tip: 0,
            max_fee: u128::MAX,
        };
        assert_eq!(
            validate_static_tx(&tx, &state),
            Err(FeeError::InvalidBlock(InvalidBlockError::EmptyDataBytes))
        );
    }

    #[test]
    fn public_tx_over_max_gas_stor_is_invalid() {
        let state = genesis();
        let tx = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 1,
            data_bytes: MAX_GAS_STOR.checked_add(1).unwrap(),
            tip: 0,
            max_fee: u128::MAX,
        };
        assert!(matches!(
            validate_static_tx(&tx, &state),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::DataBytesExceedsMax { .. }
            ))
        ));
    }

    #[test]
    fn public_tx_over_max_gas_exec_is_invalid() {
        let state = genesis();
        let tx = FeeTxView::Public {
            payer: PAYER,
            gas_limit: MAX_GAS_EXEC.checked_add(1).unwrap(),
            data_bytes: 1,
            tip: 0,
            max_fee: u128::MAX,
        };
        assert!(matches!(
            validate_static_tx(&tx, &state),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::GasLimitExceedsMax { .. }
            ))
        ));
    }

    #[test]
    fn public_tx_reserve_over_max_fee_is_invalid() {
        let state = genesis();
        let tx = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 1_000,
            data_bytes: 100,
            tip: 0,
            max_fee: 1,
        };
        assert!(matches!(
            validate_static_tx(&tx, &state),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::FeeReserveExceedsMaxFee { .. }
            ))
        ));
    }

    #[test]
    fn private_tx_is_always_statically_valid() {
        let state = genesis();
        let tx = FeeTxView::Private { payer: PAYER };
        assert!(validate_static_tx(&tx, &state).is_ok());
    }

    #[test]
    fn block_storage_cap_is_enforced_cumulatively() {
        let state = genesis();
        let big = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 1,
            data_bytes: MAX_GAS_STOR,
            tip: 0,
            max_fee: u128::MAX,
        };
        let one_more = FeeTxView::Public {
            payer: PAYER,
            gas_limit: 1,
            data_bytes: 1,
            tip: 0,
            max_fee: u128::MAX,
        };
        assert!(validate_static_block(&[big], &state).is_ok());
        assert!(matches!(
            validate_static_block(&[big, one_more], &state),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::StorageCapExceeded { .. }
            ))
        ));
    }

    /// Arithmetic of *this* function, not a statement about the live protocol: with private
    /// storage gas priced at the `PRIVATE_GAS_STOR` constant,
    /// `floor(MAX_GAS_STOR / PRIVATE_GAS_STOR) = 4` fit. The block transition charges private
    /// transactions their real wire size instead, so the number a real block admits is its own —
    /// see [`validate_static_block`]'s note.
    #[test]
    fn under_the_constant_private_size_four_private_txs_fit_this_functions_storage_cap() {
        let state = genesis();
        let txs = [FeeTxView::Private { payer: PAYER }; 4];
        assert!(validate_static_block(&txs, &state).is_ok());
    }

    #[test]
    fn accumulate_gas_used_rejects_over_cap() {
        assert_eq!(accumulate_gas_used(9, 1, 10), Ok(10));
        assert!(matches!(
            accumulate_gas_used(9, 2, 10),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::GasCapExceeded { .. }
            ))
        ));
    }

    #[test]
    fn accumulate_gas_used_rejects_u64_overflow() {
        assert!(matches!(
            accumulate_gas_used(u64::MAX, 1, u64::MAX),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::GasAccumulationOverflow
            ))
        ));
    }

    /// Q1: membership in the caller-supplied authorized set, whether the payer
    /// got there as a signer or as a sponsor outside the witness set.
    #[test]
    fn authorize_payer_requires_membership_in_the_authorized_set() {
        assert!(authorize_payer(PAYER, &[PAYER, OTHER]).is_ok());
        // Sponsored: the payer is authorized without being a transaction signer.
        assert!(authorize_payer(PAYER, &[OTHER, PAYER]).is_ok());
        assert_eq!(
            authorize_payer(PAYER, &[OTHER]),
            Err(FeeError::InvalidBlock(InvalidBlockError::UnauthorizedPayer))
        );
        assert_eq!(
            authorize_payer(PAYER, &[]),
            Err(FeeError::InvalidBlock(InvalidBlockError::UnauthorizedPayer))
        );
    }

    /// Q2: deployments are priced as public transactions, not fee-exempt.
    #[test]
    fn deployment_policy_prices_deployments_as_public() {
        assert_eq!(deployment_policy(), DeploymentFeePolicy::PricedAsPublic);
    }

    #[test]
    fn authorize_private_payer_rejects_empty_signer_set() {
        assert_eq!(
            authorize_private_payer(PAYER, &[]),
            Err(FeeError::InvalidBlock(
                InvalidBlockError::EmptyPublicSignerSet
            ))
        );
    }

    #[test]
    fn authorize_private_payer_requires_membership() {
        assert!(authorize_private_payer(PAYER, &[PAYER]).is_ok());
        assert_eq!(
            authorize_private_payer(PAYER, &[OTHER]),
            Err(FeeError::InvalidBlock(InvalidBlockError::UnauthorizedPayer))
        );
    }
}
