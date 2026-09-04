//! Fee classification: which transactions are charged and which are exempt.
//!
//! Interim policy: only user-submitted public transactions are charged.
//! Private transactions stay exempt pending the private-payer (Q3) decision;
//! system injections and genesis transactions are exempt by design. Programs
//! are deployed through ordinary public transactions (via `program_loader`),
//! so deployment is charged like any other user action.
//!
//! A user public transaction that is none of those exempt shapes MUST declare a
//! fee.
//! Omitting it is rejected outright ([`ClassifyError::MissingFeeDeclaration`]).

use common::transaction::{LeeTransaction, is_cross_zone_lock, is_sequencer_stake_operation};
use fee_core::assess::FeeTxView;

/// The fee treatment of one transaction at its turn in the block.
pub enum FeeClass {
    /// No payer, no fee, no contribution to either gas total.
    Exempt,
    /// Reserved and settled through the fee subsystem.
    Charged(FeeTxView),
}

/// Why a transaction could not be classified.
#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    /// The transaction could not be serialized to measure its storage gas.
    #[error("unserializable transaction: {0}")]
    Unserializable(#[from] borsh::io::Error),
    /// A user public transaction omitted its required fee declaration. Only the
    /// system-shaped exemptions (bridge deposit, cross-zone dispatch, genesis)
    /// may omit it; exempting an arbitrary one would execute it for free.
    #[error("user public transaction omits its required fee declaration")]
    MissingFeeDeclaration,
}

/// Classifies `tx` at its turn in the block.
///
/// `is_genesis` covers the genesis block's config/supply transactions. The
/// forced fee and clock transactions never reach this classifier: the
/// transition strips them positionally before the user-transaction loop.
///
/// # Errors
///
/// [`ClassifyError::MissingFeeDeclaration`] if a user public transaction that is
/// not an exempt shape omits its fee, and [`ClassifyError::Unserializable`] if a
/// charged transaction cannot be serialized to price its storage gas.
pub fn classify(tx: &LeeTransaction, is_genesis: bool) -> Result<FeeClass, ClassifyError> {
    if is_genesis {
        return Ok(FeeClass::Exempt);
    }
    let public_tx = match tx {
        // Private transactions: exempt under the interim policy, excluded from
        // metering so free traffic cannot move the public base fee.
        LeeTransaction::PrivacyPreserving(_) => {
            return Ok(FeeClass::Exempt);
        }
        LeeTransaction::Public(public_tx) => public_tx,
    };

    // System injections carry an empty witness set and are enumerated by
    // shape: bridge deposits and cross-zone dispatches.
    if common::transaction::is_system_injection(tx) {
        return Ok(FeeClass::Exempt);
    }

    // A cross-zone outbound lock is signed by the holder but has no spendable
    // account to charge: its funds move from the holding PDA into escrow.
    if is_cross_zone_lock(tx) {
        return Ok(FeeClass::Exempt);
    }

    // Sequencer-stake lifecycle txs (stake, unstake, slash) govern committee
    // membership, not user value; a staker funds only the stake itself.
    if is_sequencer_stake_operation(tx) {
        return Ok(FeeClass::Exempt);
    }

    // a non-exempt user public transaction must declare a fee
    let Some(fee) = public_tx.message().fee else {
        return Err(ClassifyError::MissingFeeDeclaration);
    };

    let data_bytes = u64::try_from(borsh::to_vec(tx)?.len()).expect("tx size fits u64");
    Ok(FeeClass::Charged(FeeTxView::Public {
        payer: fee.payer,
        gas_limit: fee.gas_limit,
        data_bytes,
        tip: fee.tip,
        max_fee: fee.max_fee,
    }))
}
