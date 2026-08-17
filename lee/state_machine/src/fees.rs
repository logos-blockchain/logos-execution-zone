//! Fee fields and payer authorization shared by signed message kinds.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{AccountId, public_transaction::WitnessSet};

/// The payer recorded on system-generated transactions, which are fee-exempt.
pub const SYSTEM_PAYER: AccountId = AccountId::new([0_u8; 32]);

/// The signed fee fields of a transaction message. Stored flat on each message
/// kind and covered by its hash, so every witness signature authorizes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeFields {
    /// The account debited for this transaction's fee. Never inferred from the
    /// witness set: it must be designated here and authorized by a signature.
    pub payer: AccountId,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: u128,
}

impl FeeFields {
    pub const ZERO: Self = Self::new(SYSTEM_PAYER, 0, 0, 0);

    #[must_use]
    pub const fn new(payer: AccountId, gas_limit: u64, tip: u64, max_fee: u128) -> Self {
        Self {
            payer,
            gas_limit,
            tip,
            max_fee,
        }
    }
}

/// A message kind that carries fee fields under a domain-separated hash.
pub trait SignedMessage {
    fn signing_hash(&self) -> [u8; 32];
    fn payer(&self) -> AccountId;
}

/// Accounts whose valid signature over `message` accompanies the transaction:
/// the ordinary witnesses plus the fee witness, if any.
#[must_use]
pub fn fee_authorized_account_ids<M: SignedMessage>(
    message: &M,
    witness_set: &WitnessSet,
) -> Vec<AccountId> {
    let message_hash = message.signing_hash();
    witness_set
        .signatures_and_public_keys()
        .iter()
        .chain(witness_set.fee_witness())
        .filter(|(signature, public_key)| signature.is_valid_for(&message_hash, public_key))
        .map(|(_, public_key)| AccountId::from(public_key))
        .collect()
}

/// Whether the designated payer's authorization accompanies the transaction.
#[must_use]
pub fn is_fee_authorized<M: SignedMessage>(message: &M, witness_set: &WitnessSet) -> bool {
    fee_authorized_account_ids(message, witness_set).contains(&message.payer())
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

    fn message_with_fees(fees: FeeFields) -> Message {
        let (signer_key, _) = keys();
        Message::try_new_with_fees(
            [0_u32; 8],
            vec![account_id_of(&signer_key)],
            vec![0_u128.into()],
            vec![1_u8, 2, 3],
            fees,
        )
        .expect("valid message")
    }

    #[test]
    fn self_payer_is_authorized_by_ordinary_signature() {
        let (signer_key, _) = keys();
        let message =
            message_with_fees(FeeFields::new(account_id_of(&signer_key), 1_000, 0, 10_000));
        let witness_set = WitnessSet::for_message(&message, &[&signer_key]);
        assert!(is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn sponsor_payer_requires_the_fee_witness() {
        let (signer_key, sponsor_key) = keys();
        let message = message_with_fees(FeeFields::new(
            account_id_of(&sponsor_key),
            1_000,
            0,
            10_000,
        ));

        let without = WitnessSet::for_message(&message, &[&signer_key]);
        assert!(!is_fee_authorized(&message, &without));

        let with = WitnessSet::for_message(&message, &[&signer_key])
            .with_fee_signer(&message, &sponsor_key);
        assert!(is_fee_authorized(&message, &with));
        assert!(with.is_valid_for(&message));
    }

    #[test]
    fn tampered_fee_fields_invalidate_every_signature() {
        // The fee fields are inside the signed hash: raising gas_limit after
        // signing must break both the ordinary and the fee-witness signatures.
        let (signer_key, sponsor_key) = keys();
        let message = message_with_fees(FeeFields::new(
            account_id_of(&sponsor_key),
            1_000,
            0,
            10_000,
        ));
        let witness_set = WitnessSet::for_message(&message, &[&signer_key])
            .with_fee_signer(&message, &sponsor_key);

        let mut tampered = message;
        tampered.gas_limit = 999_999;
        assert!(!witness_set.is_valid_for(&tampered));
        assert!(!is_fee_authorized(&tampered, &witness_set));
    }

    #[test]
    fn invalid_sponsor_signature_invalidates_the_witness_set() {
        let (signer_key, sponsor_key) = keys();
        let message = message_with_fees(FeeFields::ZERO);
        let other =
            Message::try_new_with_fees([1_u32; 8], vec![], vec![], vec![9_u8], FeeFields::ZERO)
                .expect("valid message");
        // Fee witness signs a DIFFERENT message: the set must be invalid.
        let witness_set =
            WitnessSet::for_message(&message, &[&signer_key]).with_fee_signer(&other, &sponsor_key);
        assert!(!witness_set.is_valid_for(&message));
    }

    #[test]
    fn zero_fields_round_trip_and_default_constructor_matches() {
        let message = message_with_fees(FeeFields::ZERO);
        assert_eq!(message.fees(), FeeFields::ZERO);
        let bytes = borsh::to_vec(&message).expect("serializes");
        let back: Message = borsh::from_slice(&bytes).expect("deserializes");
        assert_eq!(back, message);
    }
}
