use borsh::{BorshDeserialize, BorshSerialize};

use crate::{PrivateKey, PublicKey, Signature, fees::SignedMessage};

/// One witness: a signature and the public key it verifies under.
pub type Witness = (Signature, PublicKey);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) signatures_and_public_keys: Vec<(Signature, PublicKey)>,
    /// Authorization for a payer outside the witness set (a sponsored
    /// transaction): the payer's public key and its signature over the same
    /// message hash the other witnesses sign.
    pub(crate) fee_witness: Option<(Signature, PublicKey)>,
}

impl WitnessSet {
    #[must_use]
    pub fn for_message<M: SignedMessage>(message: &M, private_keys: &[&PrivateKey]) -> Self {
        let message_hash = message.signing_hash();
        let signatures_and_public_keys = private_keys
            .iter()
            .map(|&key| {
                (
                    Signature::new(key, &message_hash),
                    PublicKey::new_from_private_key(key),
                )
            })
            .collect();
        Self {
            signatures_and_public_keys,
            fee_witness: None,
        }
    }

    /// Adds the fee witness for a sponsoring payer that is not among the
    /// transaction's signers.
    #[must_use]
    pub fn with_fee_signer<M: SignedMessage>(
        mut self,
        message: &M,
        payer_key: &PrivateKey,
    ) -> Self {
        self.fee_witness = Some((
            Signature::new(payer_key, &message.signing_hash()),
            PublicKey::new_from_private_key(payer_key),
        ));
        self
    }

    /// Every signature present — witness signatures and the fee witness alike —
    /// verifies against `message`'s hash.
    #[must_use]
    pub fn is_valid_for<M: SignedMessage>(&self, message: &M) -> bool {
        let message_hash = message.signing_hash();
        self.signatures_and_public_keys()
            .iter()
            .chain(self.fee_witness())
            .all(|(signature, public_key)| signature.is_valid_for(&message_hash, public_key))
    }

    #[must_use]
    pub fn signatures_and_public_keys(&self) -> &[(Signature, PublicKey)] {
        &self.signatures_and_public_keys
    }

    #[must_use]
    pub const fn fee_witness(&self) -> Option<&Witness> {
        self.fee_witness.as_ref()
    }

    /// The exact inverse of [`Self::from_parts`]: returning the witness signatures alone would
    /// drop a sponsor's fee authorization on every round trip, with nothing to catch it.
    #[must_use]
    pub fn into_raw_parts(self) -> (Vec<Witness>, Option<Witness>) {
        (self.signatures_and_public_keys, self.fee_witness)
    }

    /// Shorthand for [`Self::from_parts`] with no fee witness.
    #[must_use]
    pub const fn from_raw_parts(signatures_and_public_keys: Vec<(Signature, PublicKey)>) -> Self {
        Self {
            signatures_and_public_keys,
            fee_witness: None,
        }
    }

    #[must_use]
    pub const fn from_parts(
        signatures_and_public_keys: Vec<Witness>,
        fee_witness: Option<Witness>,
    ) -> Self {
        Self {
            signatures_and_public_keys,
            fee_witness,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountId, public_transaction::Message};

    #[test]
    fn for_message_constructor() {
        let key1 = PrivateKey::try_new([1; 32]).unwrap();
        let key2 = PrivateKey::try_new([2; 32]).unwrap();
        let pubkey1 = PublicKey::new_from_private_key(&key1);
        let pubkey2 = PublicKey::new_from_private_key(&key2);
        let addr1 = AccountId::from(&pubkey1);
        let addr2 = AccountId::from(&pubkey2);
        let nonces = vec![1_u128.into(), 2_u128.into()];
        let instruction = vec![1, 2, 3, 4];
        let message = Message::new_feeless([0; 8], vec![addr1, addr2], nonces, instruction);

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);

        assert_eq!(witness_set.signatures_and_public_keys.len(), 2);
        assert!(witness_set.fee_witness().is_none());

        let message_bytes = message.hash();
        for ((signature, public_key), expected_public_key) in witness_set
            .signatures_and_public_keys
            .into_iter()
            .zip([pubkey1, pubkey2])
        {
            assert_eq!(public_key, expected_public_key);
            assert!(signature.is_valid_for(&message_bytes, &expected_public_key));
        }
    }

    /// `into_raw_parts` must be the exact inverse of `from_parts`. A version that returned only
    /// the witness signatures would silently destroy a sponsor's fee authorization here.
    #[test]
    fn raw_parts_roundtrip_preserves_the_fee_witness() {
        let signer = PrivateKey::try_new([1; 32]).unwrap();
        let sponsor = PrivateKey::try_new([3; 32]).unwrap();
        let message = Message::new_feeless(
            [0; 8],
            vec![AccountId::from(&PublicKey::new_from_private_key(&signer))],
            vec![0_u128.into()],
            vec![1, 2, 3, 4],
        );

        let original =
            WitnessSet::for_message(&message, &[&signer]).with_fee_signer(&message, &sponsor);
        assert!(original.fee_witness().is_some());

        let (signatures_and_public_keys, fee_witness) = original.clone().into_raw_parts();
        let rebuilt = WitnessSet::from_parts(signatures_and_public_keys, fee_witness);

        assert_eq!(rebuilt, original);
        assert_eq!(
            rebuilt.fee_witness(),
            original.fee_witness(),
            "the fee witness must survive a raw-parts round trip"
        );
    }

    #[test]
    fn raw_parts_roundtrip_without_a_fee_witness() {
        let signer = PrivateKey::try_new([1; 32]).unwrap();
        let original = WitnessSet::from_raw_parts(vec![(
            Signature::new_for_tests([7; 64]),
            PublicKey::new_from_private_key(&signer),
        )]);

        let (signatures_and_public_keys, fee_witness) = original.clone().into_raw_parts();
        assert!(fee_witness.is_none());
        assert_eq!(
            WitnessSet::from_parts(signatures_and_public_keys, fee_witness),
            original
        );
    }
}
