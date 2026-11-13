use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
use sha2::{Digest as _, digest::FixedOutput as _};

use crate::{
    InvalidTransaction,
    public_transaction::{Message, WitnessSet},
};

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
        self.message.nonces.keys().copied().collect()
    }

    #[must_use]
    pub fn affected_public_account_ids(&self) -> Vec<AccountId> {
        let mut acc_set = self
            .signer_account_ids()
            .into_iter()
            .collect::<HashSet<_>>();
        acc_set.insert(self.message.execution.root.to.account_id);
        acc_set.extend(
            self.message
                .public_context
                .actors
                .iter()
                .map(|actor| actor.account_id),
        );

        acc_set.into_iter().collect()
    }

    pub fn check_stateless(&self) -> Result<Vec<AccountId>, InvalidTransaction> {
        if !self.message.public_context.promotions.is_empty() {
            return Err(InvalidTransaction::PublicPromotions);
        }
        let signers = self.signer_account_ids();
        if self.witness_set.entries().len() != signers.len() {
            return Err(InvalidTransaction::Nonces);
        }
        self.message.check_signers()?;
        Ok(signers)
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
    use std::collections::BTreeMap;

    use lee_core::{
        account::{Account, Actor, Nonce},
        native_token::Message as NativeMessage,
        signing_key::SIGNATURE_PROGRAM_ID,
    };
    use sha2::{Digest as _, digest::FixedOutput as _};

    use crate::{
        AccountId, InvalidTransaction, PublicTransaction, V03State,
        error::LeeError,
        public_transaction::{Message, WitnessSet},
        test_utils::{TestSigner, witness_for},
        validated_state_diff::ValidatedStateDiff,
    };

    fn keys_for_tests() -> (TestSigner, TestSigner, AccountId, AccountId) {
        let key1 = TestSigner::new(1);
        let key2 = TestSigner::new(2);
        let addr1 = key1.account_id();
        let addr2 = key2.account_id();
        (key1, key2, addr1, addr2)
    }

    const fn transfer_to(recipient: AccountId) -> NativeMessage {
        NativeMessage::Transfer {
            to: recipient,
            amount: 1337,
        }
    }

    fn state_for_tests() -> V03State {
        let (_, _, addr1, addr2) = keys_for_tests();
        let initial_data = [(addr1, 10000), (addr2, 20000)];
        V03State::new().with_public_account_balances(initial_data)
    }

    fn signed(message: Message, keys: &[&TestSigner]) -> PublicTransaction {
        let witness_set = witness_for(&message, keys);
        PublicTransaction::new(message, witness_set)
    }

    fn transaction_for_tests() -> PublicTransaction {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let nonces = BTreeMap::from([(addr1, Nonce(0)), (addr2, Nonce(0))]);
        let message = Message::try_new(
            Actor::native_balance(addr1),
            vec![Actor::native_balance(addr1), Actor::native_balance(addr2)],
            nonces,
            transfer_to(addr2),
        )
        .unwrap();

        signed(message, &[&key1, &key2])
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
                71, 13, 168, 99, 56, 45, 253, 63, 38, 140, 251, 100, 28, 170, 206, 171, 97, 41, 20,
                44, 57, 70, 40, 72, 100, 174, 207, 38, 254, 141, 45, 242,
            ]),
            AccountId::new([
                208, 3, 160, 36, 101, 168, 244, 147, 67, 251, 252, 49, 104, 184, 38, 49, 254, 77,
                30, 17, 228, 136, 189, 193, 12, 244, 90, 29, 80, 105, 188, 200,
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
    fn witness_set_cannot_have_duplicate_signers() {
        let (key1, _, _, addr2) = keys_for_tests();
        let state = state_for_tests();
        // its nonce matches the current state, so only the repeat is at fault
        let mut message = transaction_for_tests().message;
        message.nonces.remove(&addr2);
        message.public_context.authorized_accounts.remove(&addr2);

        let tx = signed(message, &[&key1, &key1]);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(
            result,
            Err(LeeError::InvalidInput(msg)) if msg == InvalidTransaction::Nonces.to_string()
        ));
    }

    #[test]
    fn nonces_must_name_exactly_the_signers() {
        let (key1, key2, _, addr2) = keys_for_tests();
        let mut message = transaction_for_tests().message;
        message.nonces.remove(&addr2);

        let message_with_keys =
            message.message_with_keys(&[key1.key_state(Nonce(1)), key2.key_state(Nonce(1))]);
        let witness_set = WitnessSet::from_raw_parts(vec![
            key1.entry(Nonce(0), &message_with_keys),
            key2.entry(Nonce(0), &message_with_keys),
        ]);
        let tx = PublicTransaction::new(message, witness_set);
        assert_eq!(tx.check_stateless(), Err(InvalidTransaction::Nonces));
    }

    #[test]
    fn nonces_cannot_name_an_account_that_does_not_sign() {
        let (key1, ..) = keys_for_tests();
        let tx = signed(transaction_for_tests().message, &[&key1]);
        assert_eq!(tx.check_stateless(), Err(InvalidTransaction::Nonces));
    }

    #[test]
    fn authorized_accounts_must_be_the_signers() {
        let (key1, key2, _, addr2) = keys_for_tests();
        let mut message = transaction_for_tests().message;
        message.public_context.authorized_accounts.remove(&addr2);

        let tx = signed(message, &[&key1, &key2]);
        assert_eq!(
            tx.check_stateless(),
            Err(InvalidTransaction::AuthorizedAccounts)
        );
    }

    #[test]
    fn each_nonce_pairs_with_its_account_whatever_the_signature_order() {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let state = V03State::new().with_public_accounts([
            (addr1, Account::funded(10000)),
            (
                addr2,
                Account {
                    nonce: Nonce(1),
                    ..Account::funded(20000)
                }
                .with_actor_state(SIGNATURE_PROGRAM_ID, key2.key_state(Nonce(1)).into()),
            ),
        ]);
        let mut message = transaction_for_tests().message;
        message.nonces.insert(addr2, Nonce(1));

        for keys in [[&key1, &key2], [&key2, &key1]] {
            let tx = signed(message.clone(), &keys);
            assert!(ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).is_ok());
        }
    }

    #[test]
    fn a_public_transaction_cannot_select_promotions() {
        let (key1, key2, ..) = keys_for_tests();
        let mut message = transaction_for_tests().message;
        message.public_context.promotions.insert(0);

        let tx = signed(message, &[&key1, &key2]);
        let rejection = InvalidTransaction::PublicPromotions;
        assert_eq!(tx.check_stateless(), Err(rejection));
        assert!(matches!(
            ValidatedStateDiff::from_public_transaction(&tx, &state_for_tests(), 1, 0),
            Err(LeeError::InvalidInput(msg)) if msg == rejection.to_string()
        ));
    }

    #[test]
    fn all_signatures_must_be_valid() {
        let state = state_for_tests();
        let mut tx = transaction_for_tests();
        let first = tx.signer_account_ids()[0];
        let last = tx.witness_set.entries[0].auth_data.len() - 1;
        tx.witness_set.entries[0].auth_data[last] ^= 1;
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(
            result,
            Err(LeeError::InvalidInput(msg))
                if msg == format!("Signer {first} fails authentication: invalid signature")
        ));
    }

    #[test]
    fn nonces_must_match_the_state_current_nonces() {
        let (key1, key2, _, addr2) = keys_for_tests();
        let state = state_for_tests();
        let mut message = transaction_for_tests().message;
        message.nonces.insert(addr2, Nonce(1));

        let tx = signed(message, &[&key1, &key2]);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(LeeError::InvalidInput(_))));
    }

    #[test]
    fn empty_transaction_is_rejected() {
        let state = state_for_tests();
        let message = Message::new_preserialized(
            Actor::native_balance(AccountId::default()),
            vec![0; 4],
            vec![],
            BTreeMap::new(),
            None,
        );
        let witness_set = WitnessSet::from_raw_parts(vec![]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        assert!(matches!(result, Err(LeeError::InvalidInput(_))));
    }

    #[test]
    fn program_id_must_belong_to_builtin_program_ids() {
        let (key1, key2, addr1, addr2) = keys_for_tests();
        let state = state_for_tests();
        let nonces = BTreeMap::from([(addr1, Nonce(0)), (addr2, Nonce(0))]);
        let instruction = 1337;
        let unknown_program_id = AccountId::from_builtin_program([0xdead_beef; 8]);
        let to = Actor::new(addr1, unknown_program_id);
        let message = Message::try_new(
            to,
            vec![to, Actor::native_balance(addr2)],
            nonces,
            instruction,
        )
        .unwrap();

        let tx = signed(message, &[&key1, &key2]);
        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);
        // Named at the transaction root, so it is detectable before execution and stays
        // non-chargeable.
        assert!(matches!(
            result,
            Err(LeeError::UnknownProgram { at_root: true })
        ));
    }

    #[test]
    fn witness_entries_must_follow_the_nonces_order() {
        let tx = transaction_for_tests();
        let first = tx.signer_account_ids()[0];
        let mut entries = tx.witness_set.into_raw_parts();
        entries.swap(0, 1);

        let tx = PublicTransaction::new(tx.message, WitnessSet::from_raw_parts(entries));
        assert!(matches!(
            ValidatedStateDiff::from_public_transaction(&tx, &state_for_tests(), 1, 0),
            Err(LeeError::InvalidInput(msg)) if msg == format!(
                "Signer {first} fails authentication: revealed key does not give the account id"
            )
        ));
    }

    #[test]
    fn a_witness_entry_of_an_unlisted_account_is_rejected() {
        let mut tx = transaction_for_tests();
        let first = tx.signer_account_ids()[0];
        let stranger = TestSigner::new(3);
        let message_with_keys = tx
            .message
            .message_with_keys(&[stranger.key_state(Nonce(1)), tx.witness_set.entries[1].next]);
        tx.witness_set.entries[0] = stranger.entry(Nonce(0), &message_with_keys);
        assert!(matches!(
            ValidatedStateDiff::from_public_transaction(&tx, &state_for_tests(), 1, 0),
            Err(LeeError::InvalidInput(msg)) if msg == format!(
                "Signer {first} fails authentication: revealed key does not give the account id"
            )
        ));
    }
}
