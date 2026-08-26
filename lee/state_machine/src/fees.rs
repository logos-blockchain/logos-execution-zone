//! Fee fields and payer authorization shared by signed message kinds.

use borsh::{BorshDeserialize, BorshSerialize};

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
}

/// The accounts whose valid signature over `message` accompanies the
/// transaction.
#[must_use]
pub fn fee_authorized_account_ids<M: SignedMessage>(
    message: &M,
    witness_set: &WitnessSet,
) -> Vec<AccountId> {
    let message_hash = message.signing_hash();
    witness_set
        .signatures_and_public_keys()
        .iter()
        .filter(|(signature, public_key)| signature.is_valid_for(&message_hash, public_key))
        .map(|(_, public_key)| AccountId::from(public_key))
        .collect()
}

/// Whether the transaction's fee is authorized: a fee-exempt message always is;
/// a charged message requires its designated payer to be among the signers.
#[must_use]
pub fn is_fee_authorized<M: SignedMessage>(message: &M, witness_set: &WitnessSet) -> bool {
    message
        .payer()
        .is_none_or(|payer| fee_authorized_account_ids(message, witness_set).contains(&payer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PrivateKey, PublicKey,
        public_transaction::{Message, WitnessSet},
    };

    fn keys() -> (PrivateKey, PrivateKey) {
        (
            PrivateKey::try_new([1_u8; 32]).expect("valid key"),
            PrivateKey::try_new([2_u8; 32]).expect("valid key"),
        )
    }

    fn account_id_of(key: &PrivateKey) -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(key))
    }

    fn charged_message(payer: AccountId) -> Message {
        Message::try_new_with_fees(
            [0_u32; 8],
            vec![account_id_of(&keys().0)],
            vec![0_u128.into()],
            vec![1_u8, 2, 3],
            FeeDeclaration::new(payer, 1_000, 0, 10_000),
        )
        .expect("valid message")
    }

    fn exempt_message() -> Message {
        Message::try_new(
            [0_u32; 8],
            vec![account_id_of(&keys().0)],
            vec![0_u128.into()],
            vec![1_u8, 2, 3],
        )
        .expect("valid message")
    }

    #[test]
    fn self_payer_is_authorized_by_ordinary_signature() {
        let (signer_key, _) = keys();
        let message = charged_message(account_id_of(&signer_key));
        let witness_set = WitnessSet::for_message(&message, &[&signer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn a_co_signing_payer_is_authorized() {
        // The payer need not own an `account_id`; any co-signer may pay.
        let (signer_key, payer_key) = keys();
        let message = charged_message(account_id_of(&payer_key));
        let witness_set = WitnessSet::for_message(&message, &[&signer_key, &payer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn a_payer_outside_the_witness_set_is_unauthorized() {
        // Third-party (non-signing) sponsorship is no longer possible: the
        // payer must be in the witness set.
        let (signer_key, payer_key) = keys();
        let message = charged_message(account_id_of(&payer_key));
        let witness_set = WitnessSet::for_message(&message, &[&signer_key]);
        assert!(!is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn an_exempt_message_is_always_authorized() {
        let (signer_key, _) = keys();
        let message = exempt_message();
        assert_eq!(message.fee, None);
        let witness_set = WitnessSet::for_message(&message, &[&signer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn tampered_fee_fields_invalidate_every_signature() {
        // The fee fields are inside the signed hash: raising gas_limit after
        // signing must break the payer's signature.
        let (signer_key, _) = keys();
        let message = charged_message(account_id_of(&signer_key));
        let witness_set = WitnessSet::for_message(&message, &[&signer_key]);

        let mut tampered = message;
        tampered
            .fee
            .as_mut()
            .expect("charged message has a fee")
            .gas_limit = 999_999;
        assert!(!witness_set.is_valid_for(&tampered));
        assert!(!is_fee_authorized(&tampered, &witness_set));
    }

    #[test]
    fn exempt_and_charged_round_trip() {
        for message in [exempt_message(), charged_message(account_id_of(&keys().0))] {
            let bytes = borsh::to_vec(&message).expect("serializes");
            let back: Message = borsh::from_slice(&bytes).expect("deserializes");
            assert_eq!(back, message);
        }
    }
}
