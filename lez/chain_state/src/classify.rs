//! Fee classification: which transactions are charged and which are exempt.
//!
//! User public transactions are charged through their fee declaration. Private
//! transactions are charged through the fee they paid inside the proof: one
//! native credit on the fee inbox, priced at the height the proof commits to.
//! System injections and genesis transactions are exempt by design. Programs
//! are deployed through ordinary public transactions (via `program_loader`),
//! so deployment is charged like any other user action.
//!
//! A user transaction that is none of those exempt shapes MUST carry its fee.
//! Omitting it is rejected outright ([`ClassifyError::MissingFeeDeclaration`],
//! [`ClassifyError::MissingPrivateFee`]).

use common::transaction::{LeeTransaction, is_cross_zone_lock, is_sequencer_stake_operation};
use fee_core::assess::FeeTxView;
use lee::privacy_preserving_transaction::Message as PrivateMessage;
use lee_core::{
    account::Balance,
    native_token::{Effect, NATIVE_TOKEN_PROGRAM_ID},
};

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
    /// A private transaction carries no fee height, or its fee inbox effects
    /// are not exactly one native credit.
    #[error("private transaction omits its required in-proof fee")]
    MissingPrivateFee,
}

/// The amount a private transaction credits to the fee inbox, if the inbox
/// carries exactly one effect and it is a native credit.
fn private_fee_paid(message: &PrivateMessage) -> Option<Balance> {
    let inbox = system_accounts::fee_inbox_account_id();
    let action = message
        .public_actions
        .iter()
        .find(|action| action.account_id == inbox)?;
    let [effect] = action.effects.as_slice() else {
        return None;
    };
    if effect.program_account_id != NATIVE_TOKEN_PROGRAM_ID
        || effect.shard_program_account_id != NATIVE_TOKEN_PROGRAM_ID
    {
        return None;
    }
    match borsh::from_slice(&effect.data).ok()? {
        Effect::Credit(paid) => Some(paid),
        Effect::Debit(_) => None,
    }
}

/// Classifies `tx` at its turn in the block.
///
/// `is_genesis` covers the genesis block's config/supply transactions. The
/// forced fee and clock transactions never reach this classifier: the
/// transition strips them positionally before the user-transaction loop.
///
/// # Errors
///
/// - [`ClassifyError::MissingFeeDeclaration`] if a user public transaction that is not an exempt
///   shape omits its fee
/// - [`ClassifyError::MissingPrivateFee`] if a private transaction omits its in-proof fee, and
/// - [`ClassifyError::Unserializable`] if a charged transaction cannot be serialized to price its
///   storage gas.
pub fn classify(tx: &LeeTransaction, is_genesis: bool) -> Result<FeeClass, ClassifyError> {
    if is_genesis {
        return Ok(FeeClass::Exempt);
    }
    let public_tx = match tx {
        LeeTransaction::PrivacyPreserving(private_tx) => {
            let message = private_tx.message();
            let (Some(fee_height), Some(paid)) = (message.fee_height, private_fee_paid(message))
            else {
                return Err(ClassifyError::MissingPrivateFee);
            };
            return Ok(FeeClass::Charged(FeeTxView::Private { paid, fee_height }));
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

#[cfg(test)]
mod tests {
    use lee::privacy_preserving_transaction::{
        Message, PrivacyPreservingTransaction, WitnessSet, circuit::Proof,
        message::PublicActionWithID,
    };
    use lee_core::execution_state::DeferredPublicEffect;

    use super::*;

    fn native_credit(paid: Balance) -> DeferredPublicEffect {
        DeferredPublicEffect {
            program_account_id: NATIVE_TOKEN_PROGRAM_ID,
            shard_program_account_id: NATIVE_TOKEN_PROGRAM_ID,
            data: borsh::to_vec(&Effect::Credit(paid)).expect("serializes"),
        }
    }

    fn private_tx(
        inbox_effects: Vec<DeferredPublicEffect>,
        fee_height: Option<u64>,
    ) -> LeeTransaction {
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            Message {
                public_actions: vec![PublicActionWithID {
                    account_id: system_accounts::fee_inbox_account_id(),
                    effects: inbox_effects,
                }],
                fee_height,
                ..Message::default()
            },
            WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
        ))
    }

    #[test]
    fn a_private_transaction_is_charged_its_single_inbox_credit() {
        let class = classify(&private_tx(vec![native_credit(42)], Some(3)), false).unwrap();
        assert!(matches!(
            class,
            FeeClass::Charged(FeeTxView::Private {
                paid: 42,
                fee_height: 3
            })
        ));
    }

    #[test]
    fn a_private_transaction_without_exactly_one_inbox_credit_is_rejected() {
        let debit = DeferredPublicEffect {
            data: borsh::to_vec(&Effect::Debit(1)).expect("serializes"),
            ..native_credit(0)
        };
        let guest_effect = DeferredPublicEffect {
            program_account_id: lee::AccountId::new([9; 32]),
            ..native_credit(42)
        };
        for (effects, fee_height) in [
            (vec![native_credit(42)], None),
            (vec![], Some(3)),
            (vec![native_credit(42), native_credit(1)], Some(3)),
            (vec![debit], Some(3)),
            (vec![guest_effect], Some(3)),
        ] {
            assert!(matches!(
                classify(&private_tx(effects, fee_height), false),
                Err(ClassifyError::MissingPrivateFee)
            ));
        }
    }
}
