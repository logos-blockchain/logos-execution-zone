use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::AccountId;
use sha2::{Digest as _, digest::FixedOutput as _};

use crate::public_transaction::{Message, WitnessSet};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PublicTransaction {
    pub message: Message,
    pub witness_set: WitnessSet,
}

impl PublicTransaction {
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

    pub(crate) fn signer_account_ids(&self) -> Vec<AccountId> {
        self.witness_set
            .signatures_and_public_keys()
            .iter()
            .map(|(_, public_key)| AccountId::public_account_id(public_key))
            .collect()
    }

    #[must_use]
    pub fn affected_public_account_ids(&self) -> Vec<AccountId> {
        let mut acc_set = self
            .signer_account_ids()
            .into_iter()
            .collect::<HashSet<_>>();
        acc_set.extend(&self.message.account_ids);

        acc_set.into_iter().collect()
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        hasher.finalize_fixed().into()
    }
}

#[cfg(test)]
pub mod tests {
    use nssa_core::{PrivateKey, PublicKey, Signature};
    use sha2::{Digest as _, digest::FixedOutput as _};

    use crate::{
        AccountId, PublicTransaction, V03State,
        error::NssaError,
        program::Program,
        public_transaction::{Message, WitnessSet},
        validated_state_diff::ValidatedStateDiff,
    };

    fn keys_for_tests() -> (PrivateKey, PrivateKey, AccountId, AccountId) {
        let key1 = PrivateKey::try_new([1; 32]).unwrap();
        let key2 = PrivateKey::try_new([2; 32]).unwrap();
        let addr1 = AccountId::public_account_id(&PublicKey::new_from_private_key(&key1));
        let addr2 = AccountId::public_account_id(&PublicKey::new_from_private_key(&key2));
        (key1, key2, addr1, addr2)
    }

    fn state_for_tests() -> V03State {
        let (_, _, addr1, addr2) = keys_for_tests();
        let initial_data = [(addr1, 10000), (addr2, 20000)];
        V03State::new_with_genesis_accounts(&initial_data, &[], 0)
    }

    fn transaction_for_tests() -> PublicTransaction {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let nonces = vec![0_u128.into(), 0_u128.into()];
        let instruction = 1337;
        let message = Message::try_new(
            Program::authenticated_transfer_program().id(),
            vec![addr1, addr2],
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
        PublicTransaction::new(message, witness_set)
    }

    #[test]
    fn new_constructor() {
        let tx = transaction_for_tests();
        let message = tx.message().clone();
        let witness_set = tx.witness_set().clone();
        let tx_from_constructor = PublicTransaction::new(message.clone(), witness_set.clone());
        assert_eq!(tx_from_constructor.message, message);
        assert_eq!(tx_from_constructor.witness_set, witness_set);
    }

    #[test]
    fn message_getter() {
        let tx = transaction_for_tests();
        assert_eq!(&tx.message, tx.message());
    }

    #[test]
    fn witness_set_getter() {
        let tx = transaction_for_tests();
        assert_eq!(&tx.witness_set, tx.witness_set());
    }

    #[test]
    fn signer_account_ids() {
        let tx = transaction_for_tests();
        let expected_signer_account_ids = vec![
            AccountId::new([
                148, 179, 206, 253, 199, 51, 82, 86, 232, 2, 152, 122, 80, 243, 54, 207, 237, 112,
                83, 153, 44, 59, 204, 49, 128, 84, 160, 227, 216, 149, 97, 102,
            ]),
            AccountId::new([
                30, 145, 107, 3, 207, 73, 192, 230, 160, 63, 238, 207, 18, 69, 54, 216, 103, 244,
                92, 94, 124, 248, 42, 16, 141, 19, 119, 18, 14, 226, 140, 204,
            ]),
        ];
        let signer_account_ids = tx.signer_account_ids();
        assert_eq!(signer_account_ids, expected_signer_account_ids);
    }

    #[test]
    fn public_transaction_encoding_bytes_roundtrip() {
        let tx = transaction_for_tests();
        let bytes = tx.to_bytes();
        let tx_from_bytes = PublicTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }

    #[test]
    fn hash_is_sha256_of_transaction_bytes() {
        let tx = transaction_for_tests();
        let hash = tx.hash();
        let expected_hash: [u8; 32] = {
            let bytes = tx.to_bytes();
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            hasher.finalize_fixed().into()
        };
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn account_id_list_cant_have_duplicates() {
        let (key1, _, addr1, _) = keys_for_tests();
        let state = state_for_tests();
        let nonces = vec![0_u128.into(), 0_u128.into()];
        let instruction = 1337;
        let message = Message::try_new(
            Program::authenticated_transfer_program().id(),
            vec![addr1, addr1],
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key1]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(NssaError::InvalidInput(_))));
    }

    #[test]
    fn number_of_nonces_must_match_number_of_signatures() {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let state = state_for_tests();
        let nonces = vec![0_u128.into()];
        let instruction = 1337;
        let message = Message::try_new(
            Program::authenticated_transfer_program().id(),
            vec![addr1, addr2],
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(NssaError::InvalidInput(_))));
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn all_signatures_must_be_valid() {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let state = state_for_tests();
        let nonces = vec![0_u128.into(), 0_u128.into()];
        let instruction = 1337;
        let message = Message::try_new(
            Program::authenticated_transfer_program().id(),
            vec![addr1, addr2],
            nonces,
            instruction,
        )
        .unwrap();

        let mut witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
        witness_set.signatures_and_public_keys[0].0 = Signature::new_for_tests([1; 64]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(NssaError::InvalidInput(_))));
    }

    #[test]
    fn nonces_must_match_the_state_current_nonces() {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let state = state_for_tests();
        let nonces = vec![0_u128.into(), 1_u128.into()];
        let instruction = 1337;
        let message = Message::try_new(
            Program::authenticated_transfer_program().id(),
            vec![addr1, addr2],
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(NssaError::InvalidInput(_))));
    }

    #[test]
    fn program_id_must_belong_to_bulitin_program_ids() {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let state = state_for_tests();
        let nonces = vec![0_u128.into(), 0_u128.into()];
        let instruction = 1337;
        let unknown_program_id = [0xdead_beef; 8];
        let message =
            Message::try_new(unknown_program_id, vec![addr1, addr2], nonces, instruction).unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(NssaError::InvalidInput(_))));
    }
}
