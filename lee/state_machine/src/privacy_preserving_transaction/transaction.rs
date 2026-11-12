use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
use sha2::{Digest as _, digest::FixedOutput as _};

use super::{
    circuit::{Proof, ProofDigest},
    message::Message,
    witness_set::WitnessSet,
};
use crate::InvalidTransaction;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PrivacyPreservingTransaction<P = Proof> {
    pub message: Message,
    pub witness_set: WitnessSet<P>,
}

impl<P> PrivacyPreservingTransaction<P> {
    #[must_use]
    pub const fn new(message: Message, witness_set: WitnessSet<P>) -> Self {
        Self {
            message,
            witness_set,
        }
    }

    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    #[must_use]
    pub const fn witness_set(&self) -> &WitnessSet<P> {
        &self.witness_set
    }

    pub fn check_stateless(&self) -> Result<Vec<AccountId>, InvalidTransaction> {
        let signers = self.signer_account_ids();
        self.message.check_signers(&signers)?;
        if !self.witness_set.signatures_are_valid_for(&self.message) {
            return Err(InvalidTransaction::Signature);
        }
        Ok(signers)
    }

    pub(crate) fn signer_account_ids(&self) -> Vec<AccountId> {
        self.witness_set
            .signatures_and_public_keys()
            .iter()
            .map(|(_, public_key)| AccountId::from(public_key))
            .collect()
    }

    #[must_use]
    pub fn affected_public_account_ids(&self) -> Vec<AccountId> {
        let mut acc_set = self
            .signer_account_ids()
            .into_iter()
            .collect::<HashSet<_>>();
        acc_set.extend(self.message.public_account_ids());

        acc_set.into_iter().collect()
    }
}

impl PrivacyPreservingTransaction<ProofDigest> {
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let bytes = borsh::to_vec(self).expect("Autoderived borsh serialization failure");
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        hasher.finalize_fixed().into()
    }

    #[must_use]
    pub fn hydrate(&self, proof: Proof) -> Option<PrivacyPreservingTransaction> {
        (proof.digest() == self.witness_set.proof).then(|| PrivacyPreservingTransaction {
            message: self.message.clone(),
            witness_set: WitnessSet {
                signatures_and_public_keys: self.witness_set.signatures_and_public_keys.clone(),
                proof,
            },
        })
    }
}

impl PrivacyPreservingTransaction {
    #[must_use]
    pub fn digested(&self) -> PrivacyPreservingTransaction<ProofDigest> {
        PrivacyPreservingTransaction {
            message: self.message.clone(),
            witness_set: WitnessSet {
                signatures_and_public_keys: self.witness_set.signatures_and_public_keys.clone(),
                proof: self.witness_set.proof.digest(),
            },
        }
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.digested().hash()
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use crate::{
        AccountId, PrivacyPreservingTransaction, PrivateKey, PublicKey,
        privacy_preserving_transaction::{
            circuit::Proof, message::tests::message_for_tests, witness_set::WitnessSet,
        },
    };

    fn keys_for_tests() -> (PrivateKey, PrivateKey, AccountId, AccountId) {
        let key1 = PrivateKey::try_new([1; 32]).unwrap();
        let key2 = PrivateKey::try_new([2; 32]).unwrap();
        let addr1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
        let addr2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
        (key1, key2, addr1, addr2)
    }

    fn proof_for_tests() -> Proof {
        Proof(vec![1, 2, 3, 4, 5])
    }

    fn transaction_for_tests() -> PrivacyPreservingTransaction {
        let (key1, key2, _, _) = keys_for_tests();

        let message = message_for_tests();

        let witness_set = WitnessSet::for_message(&message, proof_for_tests(), &[&key1, &key2]);
        PrivacyPreservingTransaction::new(message, witness_set)
    }

    #[test]
    fn privacy_preserving_transaction_encoding_bytes_roundtrip() {
        let tx = transaction_for_tests();
        let bytes = tx.to_bytes();
        let tx_from_bytes = PrivacyPreservingTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }

    #[test]
    fn a_proof_digest_is_the_tagged_sha256_of_the_proof_bytes() {
        let proof = Proof(vec![0; 32]);
        let tag = b"/LEE/v0.3/ProofDigest/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let expected: [u8; 32] = Sha256::digest([&tag[..], &proof.0].concat()).into();

        assert_eq!(borsh::to_vec(&proof.digest()).unwrap(), expected);
    }

    #[test]
    fn the_digest_form_replaces_only_the_proof() {
        let tx = transaction_for_tests();

        let digested = tx.digested();

        assert_eq!(digested.message(), tx.message());
        assert_eq!(
            digested.witness_set().signatures_and_public_keys(),
            tx.witness_set().signatures_and_public_keys()
        );
        assert_eq!(*digested.witness_set().proof(), proof_for_tests().digest());
    }

    #[test]
    fn hash_is_sha256_of_the_digest_form_bytes() {
        let tx = transaction_for_tests();
        let expected: [u8; 32] = Sha256::digest(borsh::to_vec(&tx.digested()).unwrap()).into();

        assert_eq!(tx.hash(), expected);
        assert_eq!(tx.digested().hash(), expected);
    }
}
