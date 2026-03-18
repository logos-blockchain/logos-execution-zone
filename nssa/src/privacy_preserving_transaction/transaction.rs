use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    Commitment, CommitmentSetDigest, Nullifier, PrivacyPreservingCircuitOutput,
    account::{Account, AccountWithMetadata},
};
use sha2::{Digest as _, digest::FixedOutput as _};

use super::{message::Message, witness_set::WitnessSet};
use crate::{
    AccountId, V02State,
    error::NssaError,
    privacy_preserving_transaction::{circuit::Proof, message::EncryptedAccountData},
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PrivacyPreservingTransaction {
    pub message: Message,
    pub witness_set: WitnessSet,
}

impl PrivacyPreservingTransaction {
    #[must_use]
    pub const fn new(message: Message, witness_set: WitnessSet) -> Self {
        Self {
            message,
            witness_set,
        }
    }

    pub(crate) fn validate_and_produce_public_state_diff(
        &self,
        state: &V02State,
    ) -> Result<HashMap<AccountId, Account>, NssaError> {
        let message = &self.message;
        let witness_set = &self.witness_set;

        // 1. Commitments or nullifiers are non empty
        if message.new_commitments.is_empty() && message.new_nullifiers.is_empty() {
            return Err(NssaError::InvalidInput(
                "Empty commitments and empty nullifiers found in message".into(),
            ));
        }

        // 2. Check there are no duplicate account_ids in the public_account_ids list.
        if n_unique(&message.public_account_ids) != message.public_account_ids.len() {
            return Err(NssaError::InvalidInput(
                "Duplicate account_ids found in message".into(),
            ));
        }

        // Check there are no duplicate nullifiers in the new_nullifiers list
        if n_unique(&message.new_nullifiers) != message.new_nullifiers.len() {
            return Err(NssaError::InvalidInput(
                "Duplicate nullifiers found in message".into(),
            ));
        }

        // Check there are no duplicate commitments in the new_commitments list
        if n_unique(&message.new_commitments) != message.new_commitments.len() {
            return Err(NssaError::InvalidInput(
                "Duplicate commitments found in message".into(),
            ));
        }

        // 3. Nonce checks and Valid signatures
        // Check exactly one nonce is provided for each signature
        if message.nonces.len() != witness_set.signatures_and_public_keys.len() {
            return Err(NssaError::InvalidInput(
                "Mismatch between number of nonces and signatures/public keys".into(),
            ));
        }

        // Check the signatures are valid
        if !witness_set.signatures_are_valid_for(message) {
            return Err(NssaError::InvalidInput(
                "Invalid signature for given message and public key".into(),
            ));
        }

        let signer_account_ids = self.signer_account_ids();
        // Check nonces corresponds to the current nonces on the public state.
        for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
            let current_nonce = state.get_account_by_id(*account_id).nonce;
            if current_nonce != *nonce {
                return Err(NssaError::InvalidInput("Nonce mismatch".into()));
            }
        }

        // Build pre_states for proof verification
        let public_pre_states: Vec<_> = message
            .public_account_ids
            .iter()
            .map(|account_id| {
                AccountWithMetadata::new(
                    state.get_account_by_id(*account_id),
                    signer_account_ids.contains(account_id),
                    *account_id,
                )
            })
            .collect();

        // 4. Proof verification
        check_privacy_preserving_circuit_proof_is_valid(
            &witness_set.proof,
            &public_pre_states,
            &message.public_post_states,
            &message.encrypted_private_post_states,
            &message.new_commitments,
            &message.new_nullifiers,
        )?;

        // 5. Commitment freshness
        state.check_commitments_are_new(&message.new_commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&message.new_nullifiers)?;

        Ok(message
            .public_account_ids
            .iter()
            .copied()
            .zip(message.public_post_states.clone())
            .collect())
    }

    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    #[must_use]
    pub const fn witness_set(&self) -> &WitnessSet {
        &self.witness_set
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        hasher.finalize_fixed().into()
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
        acc_set.extend(&self.message.public_account_ids);

        acc_set.into_iter().collect()
    }
}

fn check_privacy_preserving_circuit_proof_is_valid(
    proof: &Proof,
    public_pre_states: &[AccountWithMetadata],
    public_post_states: &[Account],
    encrypted_private_post_states: &[EncryptedAccountData],
    new_commitments: &[Commitment],
    new_nullifiers: &[(Nullifier, CommitmentSetDigest)],
) -> Result<(), NssaError> {
    let output = PrivacyPreservingCircuitOutput {
        public_pre_states: public_pre_states.to_vec(),
        public_post_states: public_post_states.to_vec(),
        ciphertexts: encrypted_private_post_states
            .iter()
            .cloned()
            .map(|value| value.ciphertext)
            .collect(),
        new_commitments: new_commitments.to_vec(),
        new_nullifiers: new_nullifiers.to_vec(),
    };
    proof
        .is_valid_for(&output)
        .then_some(())
        .ok_or(NssaError::InvalidPrivacyPreservingProof)
}

fn n_unique<T: Eq + Hash>(data: &[T]) -> usize {
    let set: HashSet<&T> = data.iter().collect();
    set.len()
}

#[cfg(test)]
mod tests {
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
}
