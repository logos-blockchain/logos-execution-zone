use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    PrivateKey, PublicKey, Signature,
    privacy_preserving_transaction::{circuit::Proof, message::Message},
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) signatures_and_public_keys: Vec<(Signature, PublicKey)>,
    pub(crate) proof: Proof,
}

impl WitnessSet {
    #[must_use]
    pub fn for_message(message: &Message, proof: Proof, private_keys: &[&PrivateKey]) -> Self {
        let message_bytes = message.to_bytes();
        let signatures_and_public_keys = private_keys
            .iter()
            .map(|&key| {
                (
                    Signature::new(key, &message_bytes),
                    PublicKey::new_from_private_key(key),
                )
            })
            .collect();
        Self {
            signatures_and_public_keys,
            proof,
        }
    }

    #[must_use]
    pub fn signatures_are_valid_for(&self, message: &Message) -> bool {
        let message_bytes = message.to_bytes();
        for (signature, public_key) in self.signatures_and_public_keys() {
            if !signature.is_valid_for(&message_bytes, public_key) {
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
    pub const fn proof(&self) -> &Proof {
        &self.proof
    }

    #[must_use]
    pub fn into_raw_parts(self) -> (Vec<(Signature, PublicKey)>, Proof) {
        (self.signatures_and_public_keys, self.proof)
    }

    #[must_use]
    pub const fn from_raw_parts(
        signatures_and_public_keys: Vec<(Signature, PublicKey)>,
        proof: Proof,
    ) -> Self {
        Self {
            signatures_and_public_keys,
            proof,
        }
    }
}
