//! Fee classification: which transactions are charged and which are exempt.
//!
//! User public transactions are charged through their fee declaration. Private
//! transactions are charged through the reserve they paid inside the proof: one
//! native credit crossing into the fee inbox, settled at the block's base fees;
//! or through a declaration by one of their public signers, as public ones are.
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
use lee::{FeeDeclaration, privacy_preserving_transaction::Message as PrivateMessage};
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
    /// A private transaction carries more private actions than allowed.
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
    /// A private transaction declaring its fee also pays one inside its proof
    /// or crosses into the fee inbox.
    #[error("private transaction pays its fee both in its proof and by declaration")]
    DoubleFee,
    /// A private transaction's declared gas limit does not cover its proof's
    /// verification.
    #[error(
        "private transaction declares gas limit {gas_limit}, below the {} its proof's \
         verification costs",
        market::PRIVATE_VERIFY_GAS
    )]
    GasLimitBelowVerification { gas_limit: u64 },
    /// A private transaction's proof is longer than the fixed size its storage
    /// is charged at.
    #[error(
        "private transaction's proof is {size} bytes, more than the {} allowed",
        market::PROOF_BYTES
    )]
    OversizedProof { size: usize },
}

/// The crossings of a private transaction's boundary into the fee inbox.
fn inbox_crossings(message: &PrivateMessage) -> impl Iterator<Item = &Delivery<Actor>> {
    let inbox = Actor::native_balance(system_accounts::fee_inbox_account_id());
    message
        .execution
        .boundary
        .iter()
        .filter_map(move |step| match step {
            BoundaryStep::PrivateToPublic(delivery) if delivery.envelope.to == inbox => {
                Some(delivery)
            }
            BoundaryStep::PrivateToPublic(_)
            | BoundaryStep::PublicToPrivate(_)
            | BoundaryStep::EndPrivateSubtree
            | BoundaryStep::EndPublicSubtree => None,
        })
}

/// The view a declared fee is priced and settled by.
const fn declared_view(fee: FeeDeclaration, data_bytes: u64) -> FeeTxView {
    FeeTxView::Public {
        payer: fee.payer,
        gas_limit: fee.gas_limit,
        data_bytes,
        tip: fee.tip,
        max_fee: fee.max_fee,
    }
}

/// The reserve a private transaction credits to the fee inbox inside its proof,
/// the address it came from and the crossing carrying it, if the boundary
/// carries exactly one crossing into the inbox and it is a native credit.
fn private_fee_reserve(message: &PrivateMessage) -> Option<(AccountId, Balance, &Delivery<Actor>)> {
    let mut crossings = inbox_crossings(message);
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
/// - [`ClassifyError::MissingPrivateFee`] if a private transaction declares no fee and omits its
///   in-proof fee,
/// - [`ClassifyError::DoubleFee`] if it both declares a fee and pays one in its proof or crosses
///   into the fee inbox,
/// - [`ClassifyError::GasLimitBelowVerification`] if its declared gas limit is below
///   [`market::PRIVATE_VERIFY_GAS`],
/// - [`ClassifyError::TooManyPrivateActions`] if it carries more private actions than
///   [`market::MAX_PRIVATE_ACTIONS`],
/// - [`ClassifyError::InvalidRefundTarget`] if it names a restricted account as its refund target,
/// - [`ClassifyError::InvalidFeeFallback`] if its fee fallback replays anything but that fee
///   transfer's crossing,
/// - [`ClassifyError::OversizedProof`] if its proof is longer than [`market::PROOF_BYTES`],
/// - [`ClassifyError::Unserializable`] if a charged transaction cannot be serialized to price its
///   storage gas.
pub fn classify(tx: &LeeTransaction, is_genesis: bool) -> Result<FeeClass, ClassifyError> {
    if is_genesis {
        return Ok(FeeClass::Exempt);
    }
    let public_tx = match tx {
        LeeTransaction::PrivacyPreserving(private_tx) => {
            let execution = &private_tx.message().execution;
            let count = execution.private_actions.len();
            if count > market::MAX_PRIVATE_ACTIONS {
                return Err(ClassifyError::TooManyPrivateActions { count });
            }
            let size = private_tx.witness_set().proof().size();
            if u64::try_from(size).map_or(true, |size| size > market::PROOF_BYTES) {
                return Err(ClassifyError::OversizedProof { size });
            }
            // A public signer's declaration pays like a public transaction whose gas limit also
            // covers the proof's verification.
            if let Some(fee) = private_tx.message().fee {
                if execution.proven_fee.is_some()
                    || inbox_crossings(private_tx.message()).next().is_some()
                {
                    return Err(ClassifyError::DoubleFee);
                }
                if fee.gas_limit < market::PRIVATE_VERIFY_GAS {
                    return Err(ClassifyError::GasLimitBelowVerification {
                        gas_limit: fee.gas_limit,
                    });
                }
                return Ok(FeeClass::Charged(declared_view(fee, tx.charged_bytes()?)));
            }
            let Some((payer, reserve, crossing)) = private_fee_reserve(private_tx.message()) else {
                return Err(ClassifyError::MissingPrivateFee);
            };
            // The fallback is applied in place of the proven actions, so it must pay exactly
            // the reserve priced here: the same crossing, alone.
            if let Some(fallback) = execution
                .proven_fee
                .as_ref()
                .and_then(|fee| fee.fallback.as_ref())
                && fallback.boundary
                    != [
                        BoundaryStep::PrivateToPublic(crossing.clone()),
                        BoundaryStep::EndPublicSubtree,
                    ]
            {
                return Err(ClassifyError::InvalidFeeFallback);
            }
            if let Some(target) = execution.proven_fee.as_ref().and_then(|fee| fee.refund_to) {
                validate_reward_target(target)
                    .map_err(|reason| ClassifyError::InvalidRefundTarget { reason })?;
            }
            return Ok(FeeClass::Charged(FeeTxView::Private {
                payer,
                reserve,
                data_bytes: tx.charged_bytes()?,
            }));
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

    Ok(FeeClass::Charged(declared_view(fee, tx.charged_bytes()?)))
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
        let tx = private_tx(boundary);
        let size = tx.charged_bytes().unwrap();
        let class = classify(&tx, false).unwrap();
        assert!(matches!(
            class,
            FeeClass::Charged(FeeTxView::Private { payer, reserve: 42, data_bytes })
                if payer == self::payer().account_id && data_bytes == size
        ));
    }

    #[test]
    fn a_private_transaction_is_charged_a_fixed_proof_it_may_not_exceed() {
        let with_proof = |size| {
            let mut message = Message::default();
            message.execution.boundary = vec![
                crossing(inbox(), &native_token::Message::Credit(42)),
                BoundaryStep::EndPublicSubtree,
            ];
            LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
                message,
                WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![0; size])),
            ))
        };
        let cap = usize::try_from(market::PROOF_BYTES).unwrap();
        assert_eq!(
            with_proof(0).charged_bytes().unwrap(),
            with_proof(cap).charged_bytes().unwrap()
        );
        assert!(classify(&with_proof(cap), false).is_ok());
        assert!(matches!(
            classify(&with_proof(cap + 1), false),
            Err(ClassifyError::OversizedProof { size }) if size == cap + 1
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
            message.execution.proven_fee = Some(lee_core::ProvenFee {
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
    fn a_private_transaction_declaring_its_fee_is_priced_as_a_public_one() {
        let declared = |gas_limit, proven_fee: bool, crossing_inbox: bool| {
            let mut message = Message {
                fee: Some(lee::FeeDeclaration::new(
                    payer().account_id,
                    gas_limit,
                    3,
                    99,
                )),
                ..Message::default()
            };
            message.execution.proven_fee = proven_fee.then_some(lee_core::ProvenFee {
                refund_to: None,
                fallback: None,
            });
            if crossing_inbox {
                message.execution.boundary = vec![
                    crossing(inbox(), &native_token::Message::Credit(42)),
                    BoundaryStep::EndPublicSubtree,
                ];
            }
            LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
                message,
                WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
            ))
        };
        let gas_limit = market::PRIVATE_VERIFY_GAS;
        let tx = declared(gas_limit, false, false);
        let size = tx.charged_bytes().unwrap();
        assert!(matches!(
            classify(&tx, false),
            Ok(FeeClass::Charged(FeeTxView::Public {
                payer,
                gas_limit: limit,
                data_bytes,
                tip: 3,
                max_fee: 99,
            })) if payer == self::payer().account_id && limit == gas_limit && data_bytes == size
        ));
        assert!(matches!(
            classify(&declared(gas_limit - 1, false, false), false),
            Err(ClassifyError::GasLimitBelowVerification { gas_limit: limit })
                if limit == gas_limit - 1
        ));
        for (proven_fee, crossing_inbox) in [(true, false), (false, true)] {
            assert!(matches!(
                classify(&declared(gas_limit, proven_fee, crossing_inbox), false),
                Err(ClassifyError::DoubleFee)
            ));
        }
    }

    #[test]
    fn a_fee_fallback_must_replay_the_priced_inbox_credit_alone() {
        let credit = crossing(inbox(), &native_token::Message::Credit(42));
        let with_fallback = |boundary| {
            let mut message = Message::default();
            message.execution.boundary = vec![credit.clone(), BoundaryStep::EndPublicSubtree];
            message.execution.proven_fee = Some(lee_core::ProvenFee {
                refund_to: None,
                fallback: Some(lee_core::FeeFallback {
                    action: lee_core::PrivateAction::default(),
                    boundary,
                }),
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
