use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
use sha2::{Digest as _, digest::FixedOutput as _};

use super::{message::Message, witness_set::WitnessSet};
use crate::InvalidTransaction;

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

    pub fn check_stateless(&self) -> Result<Vec<AccountId>, InvalidTransaction> {
        let signers = self.signer_account_ids();
        let witness = self.witness_set.signatures_and_public_keys();
        if witness.len() != signers.len() {
            return Err(InvalidTransaction::Nonces);
        }
        if witness
            .iter()
            .zip(&signers)
            .any(|((_, public_key), signer)| AccountId::from(public_key) != *signer)
        {
            return Err(InvalidTransaction::SignerOrder);
        }
        self.message.check_signers()?;
        if !self.witness_set.signatures_are_valid_for(&self.message) {
            return Err(InvalidTransaction::Signature);
        }
        Ok(signers)
    }

    pub(crate) fn signer_account_ids(&self) -> Vec<AccountId> {
        self.message.nonces.keys().copied().collect()
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

#[cfg(test)]
mod tests {
    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::Proof, message::tests::message_for_tests, witness_set::WitnessSet,
        },
        test_utils::{TestSigner, privacy_signed_entry},
    };

    fn proof_for_tests() -> Proof {
        Proof(vec![1, 2, 3, 4, 5])
    }

    fn transaction_for_tests() -> PrivacyPreservingTransaction {
        let message = message_for_tests();

        let entries = [TestSigner::new(1), TestSigner::new(2)]
            .iter()
            .map(|signer| privacy_signed_entry(signer, &message))
            .collect();
        let witness_set = WitnessSet::from_raw_parts(entries, proof_for_tests());
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
