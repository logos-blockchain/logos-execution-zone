use borsh::{BorshDeserialize, BorshSerialize};

use crate::{PrivateKey, PublicKey, Signature, public_transaction::Message};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) signatures_and_public_keys: Vec<(Signature, PublicKey)>,
    pub(crate) fee_witness: Option<(Signature, PublicKey)>,
}

impl WitnessSet {
    #[must_use]
    pub fn for_message(message: &Message, private_keys: &[&PrivateKey]) -> Self {
        let message_hash = message.hash();
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

    /// Adds a sponsor's fee authorization: a signature over the same message
    /// hash by an account outside the ordinary witness set.
    #[must_use]
    pub fn with_fee_signer(mut self, message: &Message, payer_key: &PrivateKey) -> Self {
        let message_hash = message.hash();
        self.fee_witness = Some((
            Signature::new(payer_key, &message_hash),
            PublicKey::new_from_private_key(payer_key),
        ));
        self
    }

    #[must_use]
    pub const fn fee_witness(&self) -> Option<&(Signature, PublicKey)> {
        self.fee_witness.as_ref()
    }

    #[must_use]
    pub fn is_valid_for(&self, message: &Message) -> bool {
        let message_hash = message.hash();
        for (signature, public_key) in self
            .signatures_and_public_keys()
            .iter()
            .chain(self.fee_witness())
        {
            if !signature.is_valid_for(&message_hash, public_key) {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn signatures_and_public_keys(&self) -> &[(Signature, PublicKey)] {
        &self.signatures_and_public_keys
    }

    #[must_use]
    pub fn into_raw_parts(self) -> Vec<(Signature, PublicKey)> {
        self.signatures_and_public_keys
    }

    #[must_use]
    pub const fn from_raw_parts(signatures_and_public_keys: Vec<(Signature, PublicKey)>) -> Self {
        Self {
            signatures_and_public_keys,
            fee_witness: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountId;

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
        let message = Message::try_new([0; 8], vec![addr1, addr2], nonces, instruction).unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);

        assert_eq!(witness_set.signatures_and_public_keys.len(), 2);

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
}
