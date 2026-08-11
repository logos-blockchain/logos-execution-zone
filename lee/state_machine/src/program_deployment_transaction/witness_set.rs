use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;

use crate::{PrivateKey, PublicKey, Signature, program_deployment_transaction::Message};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) signature_and_public_key: Option<(Signature, PublicKey)>,
}

impl WitnessSet {
    #[must_use]
    pub fn for_message(message: &Message, private_key: Option<&PrivateKey>) -> Self {
        let message_hash = message.hash();
        let signature_and_public_key = private_key.map(|key| {
            (
                Signature::new(key, &message_hash),
                PublicKey::new_from_private_key(key),
            )
        });
        Self {
            signature_and_public_key,
        }
    }

    #[must_use]
    pub const fn none() -> Self {
        Self {
            signature_and_public_key: None,
        }
    }

    /// Whether the signature, if present, is cryptographically valid for `message`. Vacuously
    /// `true` when no signature is present; whether a signature is actually required is a policy
    /// decision made by the caller (it depends on `Program.upgrade_auth`), not this check.
    #[must_use]
    pub fn is_valid_for(&self, message: &Message) -> bool {
        let Some((signature, public_key)) = &self.signature_and_public_key else {
            return true;
        };
        signature.is_valid_for(&message.hash(), public_key)
    }

    #[must_use]
    pub fn signer_account_id(&self) -> Option<AccountId> {
        self.signature_and_public_key
            .as_ref()
            .map(|(_, public_key)| AccountId::from(public_key))
    }

    #[must_use]
    pub const fn into_raw_parts(self) -> Option<(Signature, PublicKey)> {
        self.signature_and_public_key
    }

    #[must_use]
    pub const fn from_raw_parts(signature_and_public_key: Option<(Signature, PublicKey)>) -> Self {
        Self {
            signature_and_public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WitnessSet;
    use crate::{PrivateKey, program_deployment_transaction::Message};

    #[test]
    fn none_has_no_signer_and_is_valid() {
        let message = Message::new(vec![0xca, 0xfe]);
        let witness_set = WitnessSet::none();
        assert_eq!(witness_set.signer_account_id(), None);
        assert!(witness_set.is_valid_for(&message));
    }

    #[test]
    fn for_message_produces_a_verifiable_signature() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let message = Message::new(vec![0xca, 0xfe]);
        let witness_set = WitnessSet::for_message(&message, Some(&key));
        assert!(witness_set.is_valid_for(&message));
        assert!(witness_set.signer_account_id().is_some());
    }

    #[test]
    fn signature_for_a_different_message_is_invalid() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let message = Message::new(vec![0xca, 0xfe]);
        let other_message = Message::new(vec![0xde, 0xad]);
        let witness_set = WitnessSet::for_message(&message, Some(&key));
        assert!(!witness_set.is_valid_for(&other_message));
    }
}
