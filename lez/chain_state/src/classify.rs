//! Fee classification: which transactions are charged and which are exempt.
//!
//! User public transactions are charged through their fee declaration. Private
//! transactions are charged through the reserve they paid inside the proof: one
//! native credit crossing into the fee inbox, settled at the block's base fees.
//! System injections and genesis transactions are exempt by design. Programs
//! are deployed through ordinary public transactions (via `program_loader`),
//! so deployment is charged like any other user action.
//!
//! A user transaction that is none of those exempt shapes MUST carry its fee.
//! Omitting it is rejected outright ([`ClassifyError::MissingFeeDeclaration`],
//! [`ClassifyError::MissingPrivateFee`]).

use common::transaction::{
    LeeTransaction, is_cross_zone_lock, is_sequencer_stake_operation, validate_reward_target,
};
use fee_core::{assess::FeeTxView, market};
use lee::privacy_preserving_transaction::Message as PrivateMessage;
use lee_core::{
    account::{AccountId, Actor, Balance},
    execution_state::{BoundaryStep, Delivery},
    native_token,
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
    /// A private transaction's boundary does not carry exactly one crossing
    /// into the fee inbox, or that crossing is not a native credit.
    #[error("private transaction omits its required in-proof fee")]
    MissingPrivateFee,
    /// A private transaction carries more private actions than its flat
    /// storage price covers.
    #[error(
        "private transaction carries {count} private actions, more than the {} allowed",
        market::MAX_PRIVATE_ACTIONS
    )]
    TooManyPrivateActions { count: usize },
    /// A private transaction names a restricted system account as its refund
    /// target.
    #[error("private fee refund target is invalid: {reason}")]
    InvalidRefundTarget { reason: String },
    /// A private transaction's fee fallback does not replay the inbox credit
    /// its reserve is priced from.
    #[error("private fee fallback does not replay the fee transfer alone")]
    InvalidFeeFallback,
}

/// The reserve a private transaction credits to the fee inbox inside its proof,
/// the address it came from and the crossing carrying it, if the boundary
/// carries exactly one crossing into the inbox and it is a native credit.
fn private_fee_reserve(message: &PrivateMessage) -> Option<(AccountId, Balance, &Delivery<Actor>)> {
    let inbox = Actor::native_balance(system_accounts::fee_inbox_account_id());
    let mut crossings = message
        .execution
        .boundary
        .iter()
        .filter_map(|step| match step {
            BoundaryStep::PrivateToPublic(delivery) if delivery.envelope.to == inbox => {
                Some(delivery)
            }
            BoundaryStep::PrivateToPublic(_)
            | BoundaryStep::PublicToPrivate(_)
            | BoundaryStep::EndPrivateSubtree
            | BoundaryStep::EndPublicSubtree => None,
        });
    let delivery = crossings.next()?;
    if crossings.next().is_some() {
        return None;
    }
    match borsh::from_slice(&delivery.envelope.message).ok()? {
        native_token::Message::Credit(reserve) => {
            Some((delivery.envelope.from.account_id, reserve, delivery))
        }
        native_token::Message::Transfer { .. } | native_token::Message::ReadState => None,
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
/// - [`ClassifyError::MissingPrivateFee`] if a private transaction omits its in-proof fee,
/// - [`ClassifyError::TooManyPrivateActions`] if it carries more private actions than
///   [`market::MAX_PRIVATE_ACTIONS`],
/// - [`ClassifyError::InvalidRefundTarget`] if it names a restricted account as its refund target,
/// - [`ClassifyError::InvalidFeeFallback`] if its fee fallback replays anything but that fee
///   transfer's crossing,
/// - [`ClassifyError::Unserializable`] if a charged transaction cannot be serialized to price its
///   storage gas.
pub fn classify(tx: &LeeTransaction, is_genesis: bool) -> Result<FeeClass, ClassifyError> {
    if is_genesis {
        return Ok(FeeClass::Exempt);
    }
    let public_tx = match tx {
        LeeTransaction::PrivacyPreserving(private_tx) => {
            let execution = &private_tx.message().execution;
            let Some((payer, reserve, crossing)) = private_fee_reserve(private_tx.message()) else {
                return Err(ClassifyError::MissingPrivateFee);
            };
            // The fallback is applied in place of the proven actions, so it must pay exactly
            // the reserve priced here: the same crossing, alone.
            if let Some(fallback) = execution.fee.as_ref().and_then(|fee| fee.fallback.as_ref())
                && fallback.boundary
                    != [
                        BoundaryStep::PrivateToPublic(crossing.clone()),
                        BoundaryStep::EndPublicSubtree,
                    ]
            {
                return Err(ClassifyError::InvalidFeeFallback);
            }
            let count = execution.private_actions.len();
            if count > market::MAX_PRIVATE_ACTIONS {
                return Err(ClassifyError::TooManyPrivateActions { count });
            }
            if let Some(target) = execution.fee.as_ref().and_then(|fee| fee.refund_to) {
                validate_reward_target(target)
                    .map_err(|reason| ClassifyError::InvalidRefundTarget { reason })?;
            }
            return Ok(FeeClass::Charged(FeeTxView::Private { payer, reserve }));
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
    let Some(fee) = public_tx.message().execution.fee else {
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
    use std::collections::BTreeSet;

    use lee::privacy_preserving_transaction::{
        Message, PrivacyPreservingTransaction, WitnessSet, circuit::Proof,
    };
    use lee_core::{execution_state::Delivery, program::MessageEnvelope};

    use super::*;

    fn inbox() -> Actor {
        Actor::native_balance(system_accounts::fee_inbox_account_id())
    }

    fn payer() -> Actor {
        Actor::native_balance(AccountId::new([7; 32]))
    }

    fn crossing(to: Actor, message: &native_token::Message) -> BoundaryStep {
        BoundaryStep::PrivateToPublic(Delivery {
            envelope: MessageEnvelope {
                from: payer(),
                to,
                message: borsh::to_vec(message).expect("serializes"),
            },
            inherited_authorizations: BTreeSet::new(),
            inherits_entry_authorizations: true,
            pda_seeds: BTreeSet::new(),
        })
    }

    fn private_tx(boundary: Vec<BoundaryStep>) -> LeeTransaction {
        let mut message = Message::default();
        message.execution.boundary = boundary;
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            message,
            WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
        ))
    }

    #[test]
    fn a_private_transaction_is_charged_its_single_inbox_credit() {
        let boundary = vec![
            crossing(inbox(), &native_token::Message::Credit(42)),
            BoundaryStep::EndPublicSubtree,
        ];
        let class = classify(&private_tx(boundary), false).unwrap();
        assert!(matches!(
            class,
            FeeClass::Charged(FeeTxView::Private { payer, reserve: 42 })
                if payer == self::payer().account_id
        ));
    }

    #[test]
    fn a_private_transaction_over_the_action_cap_or_refunding_a_restricted_account_is_rejected() {
        let crediting = || {
            vec![
                crossing(inbox(), &native_token::Message::Credit(42)),
                BoundaryStep::EndPublicSubtree,
            ]
        };
        let tx = |message| {
            LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
                message,
                WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
            ))
        };

        let mut capped = Message::default();
        capped.execution.boundary = crediting();
        capped.execution.private_actions =
            vec![lee_core::PrivateAction::default(); market::MAX_PRIVATE_ACTIONS + 1];
        assert!(matches!(
            classify(&tx(capped), false),
            Err(ClassifyError::TooManyPrivateActions { count })
                if count == market::MAX_PRIVATE_ACTIONS + 1
        ));

        let targeting = |target| {
            let mut message = Message::default();
            message.execution.boundary = crediting();
            message.execution.fee = Some(lee_core::ProvenFee {
                refund_to: Some(target),
                fallback: None,
            });
            tx(message)
        };
        assert!(matches!(
            classify(&targeting(system_accounts::fee_inbox_account_id()), false),
            Err(ClassifyError::InvalidRefundTarget { .. })
        ));
        assert!(matches!(
            classify(&targeting(AccountId::new([3; 32])), false),
            Ok(FeeClass::Charged(FeeTxView::Private { reserve: 42, .. }))
        ));
    }

    #[test]
    fn a_fee_fallback_must_replay_the_priced_inbox_credit_alone() {
        let credit = crossing(inbox(), &native_token::Message::Credit(42));
        let with_fallback = |boundary| {
            let mut message = Message::default();
            message.execution.boundary = vec![credit.clone(), BoundaryStep::EndPublicSubtree];
            message.execution.fee = Some(lee_core::ProvenFee {
                refund_to: None,
                fallback: Some(Box::new(lee_core::FeeFallback {
                    action: lee_core::PrivateAction::default(),
                    boundary,
                })),
            });
            LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
                message,
                WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
            ))
        };
        let elsewhere = crossing(
            Actor::native_balance(AccountId::new([3; 32])),
            &native_token::Message::Credit(42),
        );
        for boundary in [
            vec![elsewhere, BoundaryStep::EndPublicSubtree],
            vec![
                crossing(inbox(), &native_token::Message::Credit(41)),
                BoundaryStep::EndPublicSubtree,
            ],
            vec![credit.clone()],
            Vec::new(),
        ] {
            assert!(matches!(
                classify(&with_fallback(boundary), false),
                Err(ClassifyError::InvalidFeeFallback)
            ));
        }
        assert!(matches!(
            classify(
                &with_fallback(vec![credit.clone(), BoundaryStep::EndPublicSubtree]),
                false
            ),
            Ok(FeeClass::Charged(FeeTxView::Private { reserve: 42, .. }))
        ));
    }

    #[test]
    fn a_private_transaction_without_exactly_one_inbox_credit_is_rejected() {
        let credit = native_token::Message::Credit(42);
        let other = Actor::native_balance(AccountId::new([9; 32]));
        for boundary in [
            vec![],
            vec![crossing(other, &credit)],
            vec![crossing(inbox(), &credit), crossing(inbox(), &credit)],
            vec![crossing(inbox(), &native_token::Message::ReadState)],
            vec![crossing(
                inbox(),
                &native_token::Message::Transfer {
                    to: other.account_id,
                    amount: 1,
                },
            )],
        ] {
            assert!(matches!(
                classify(&private_tx(boundary), false),
                Err(ClassifyError::MissingPrivateFee)
            ));
        }
    }
}
