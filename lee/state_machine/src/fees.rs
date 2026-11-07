//! Fee fields and payer authorization shared by signed message kinds.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::Nonce;

use crate::{AccountId, Balance, Fee, Gas, public_transaction::WitnessSet};

/// The signed fee fields of a charged transaction.
///
/// Carried as `Option<FeeDeclaration>` on each message kind (`None` =
/// fee-exempt) and covered by the message hash, so every witness signature
/// authorizes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeDeclaration {
    /// The account debited for this transaction's fee. Designated explicitly
    /// here and authorized by an ordinary witness signature; never inferred
    /// from the witness set.
    pub payer: AccountId,
    pub gas_limit: Gas,
    pub tip: Fee,
    pub max_fee: Balance,
}

impl FeeDeclaration {
    #[must_use]
    pub const fn new(payer: AccountId, gas_limit: Gas, tip: Fee, max_fee: Balance) -> Self {
        Self {
            payer,
            gas_limit,
            tip,
            max_fee,
        }
    }
}

/// A message kind that carries an optional fee under a domain-separated hash.
pub trait SignedMessage {
    fn signing_hash(&self) -> [u8; 32];
    /// The designated fee payer, or `None` for a fee-exempt message.
    fn payer(&self) -> Option<AccountId>;
    fn nonces(&self) -> &BTreeMap<AccountId, Nonce>;
}

/// Whether the transaction's fee is authorized: a fee-exempt message always is;
/// a charged message requires a valid signature by its designated payer.
///
/// Checks only the witness entry at the payer's position in `nonces` — its
/// account id before its signature, so only the payer's signature is verified,
/// not every signer's.
#[must_use]
pub fn is_fee_authorized<M: SignedMessage>(message: &M, witness_set: &WitnessSet) -> bool {
    let Some(payer) = message.payer() else {
        return true;
    };
    let Some(position) = message.nonces().keys().position(|signer| *signer == payer) else {
        return false;
    };
    witness_set
        .signatures_and_public_keys()
        .get(position)
        .is_some_and(|(signature, public_key)| {
            AccountId::from(public_key) == payer
                && signature.is_valid_for(&message.signing_hash(), public_key)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::account::{Actor, Nonce};

    use super::*;
    use crate::{
        public_transaction::{Message, WitnessSet},
        test_utils::{TestSigner, witness_for},
    };

    fn keys() -> (TestSigner, TestSigner) {
        (TestSigner::new(1), TestSigner::new(2))
    }

    fn charged_message(payer: AccountId) -> Message {
        Message::try_new_with_fees(
            Actor::new(
                keys().0.account_id(),
                AccountId::from_builtin_program([0_u32; 8]),
            ),
            vec![Actor::native_balance(keys().0.account_id())],
            BTreeMap::from([(keys().0.account_id(), Nonce(0))]),
            vec![1_u8, 2, 3],
            FeeDeclaration::new(payer, 1_000, 0, 10_000),
        )
        .expect("valid message")
    }

    fn exempt_message() -> Message {
        Message::try_new(
            Actor::new(
                keys().0.account_id(),
                AccountId::from_builtin_program([0_u32; 8]),
            ),
            vec![Actor::native_balance(keys().0.account_id())],
            BTreeMap::from([(keys().0.account_id(), Nonce(0))]),
            vec![1_u8, 2, 3],
        )
        .expect("valid message")
    }

    #[test]
    fn self_payer_is_authorized_by_ordinary_signature() {
        let (signer_key, _) = keys();
        let message = charged_message(signer_key.account_id());
        let witness_set = witness_for(&message, &[&signer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn a_co_signing_payer_is_authorized() {
        // The payer need not own an `account_id`; any co-signer may pay.
        let (signer_key, payer_key) = keys();
        let mut message = charged_message(payer_key.account_id());
        message.nonces.insert(payer_key.account_id(), Nonce(0));
        message
            .public_context
            .authorized_accounts
            .insert(payer_key.account_id());
        let witness_set = witness_for(&message, &[&signer_key, &payer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn a_payer_outside_the_witness_set_is_unauthorized() {
        // Third-party (non-signing) sponsorship is no longer possible: the
        // payer must be in the witness set.
        let (signer_key, payer_key) = keys();
        let message = charged_message(payer_key.account_id());
        let witness_set = witness_for(&message, &[&signer_key]);
        assert!(!is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn an_exempt_message_is_always_authorized() {
        let (signer_key, _) = keys();
        let message = exempt_message();
        assert_eq!(message.execution.fee, None);
        let witness_set = witness_for(&message, &[&signer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn tampered_fee_declaration_invalidate_every_signature() {
        // The fee fields are inside the signed hash: raising gas_limit after
        // signing must break the payer's signature.
        let (signer_key, _) = keys();
        let message = charged_message(signer_key.account_id());
        let witness_set = witness_for(&message, &[&signer_key]);

        let mut tampered = message;
        tampered
            .execution
            .fee
            .as_mut()
            .expect("charged message has a fee")
            .gas_limit = 999_999;
        assert!(!witness_set.is_valid_for(&tampered));
        assert!(!is_fee_authorized(&tampered, &witness_set));
    }

    #[test]
    fn exempt_and_charged_round_trip() {
        for message in [exempt_message(), charged_message(keys().0.account_id())] {
            let bytes = borsh::to_vec(&message).expect("serializes");
            let back: Message = borsh::from_slice(&bytes).expect("deserializes");
            assert_eq!(back, message);
        }
    }

    #[test]
    fn a_payer_entry_off_its_nonces_position_is_unauthorized() {
        let (signer_key, payer_key) = keys();
        let mut message = charged_message(payer_key.account_id());
        message.nonces.insert(payer_key.account_id(), Nonce(0));
        message
            .public_context
            .authorized_accounts
            .insert(payer_key.account_id());
        let mut entries = witness_for(&message, &[&signer_key, &payer_key]).into_raw_parts();
        entries.swap(0, 1);
        let witness_set = WitnessSet::from_raw_parts(entries);
        assert!(!is_fee_authorized(&message, &witness_set));
    }
}
