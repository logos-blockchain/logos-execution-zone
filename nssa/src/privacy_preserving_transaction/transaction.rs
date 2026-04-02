use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::{Account, AccountId};
use sha2::{Digest as _, digest::FixedOutput as _};

use super::{message::Message, witness_set::WitnessSet};

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
