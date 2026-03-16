use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, MembershipProof, Nullifier,
    account::{Account, AccountId},
    program::ProgramId,
};

use crate::{
    error::NssaError, merkle_tree::MerkleTree,
    privacy_preserving_transaction::PrivacyPreservingTransaction, program::Program,
    program_deployment_transaction::ProgramDeploymentTransaction,
    public_transaction::PublicTransaction,
};

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) struct CommitmentSet {
    merkle_tree: MerkleTree,
    commitments: HashMap<Commitment, usize>,
    root_history: HashSet<CommitmentSetDigest>,
}

impl CommitmentSet {
    pub(crate) fn digest(&self) -> CommitmentSetDigest {
        self.merkle_tree.root()
    }

    /// Queries the `CommitmentSet` for a membership proof of commitment
    pub fn get_proof_for(&self, commitment: &Commitment) -> Option<MembershipProof> {
        let index = *self.commitments.get(commitment)?;

        self.merkle_tree
            .get_authentication_path_for(index)
            .map(|path| (index, path))
    }

    /// Inserts a list of commitments to the `CommitmentSet`.
    pub(crate) fn extend(&mut self, commitments: &[Commitment]) {
        for commitment in commitments.iter().cloned() {
            let index = self.merkle_tree.insert(commitment.to_byte_array());
            self.commitments.insert(commitment, index);
        }
        self.root_history.insert(self.digest());
    }

    fn contains(&self, commitment: &Commitment) -> bool {
        self.commitments.contains_key(commitment)
    }

    /// Initializes an empty `CommitmentSet` with a given capacity.
    /// If the capacity is not a power_of_two, then capacity is taken
    /// to be the next power_of_two.
    pub(crate) fn with_capacity(capacity: usize) -> CommitmentSet {
        Self {
            merkle_tree: MerkleTree::with_capacity(capacity),
            commitments: HashMap::new(),
            root_history: HashSet::new(),
        }
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone)]
struct NullifierSet(BTreeSet<Nullifier>);

impl NullifierSet {
    fn new() -> Self {
        Self(BTreeSet::new())
    }

    fn extend(&mut self, new_nullifiers: Vec<Nullifier>) {
        self.0.extend(new_nullifiers);
    }

    fn contains(&self, nullifier: &Nullifier) -> bool {
        self.0.contains(nullifier)
    }
}

impl BorshSerialize for NullifierSet {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.iter().collect::<Vec<_>>().serialize(writer)
    }
}

impl BorshDeserialize for NullifierSet {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vec::<Nullifier>::deserialize_reader(reader)?;

        let mut set = BTreeSet::new();
        for n in vec {
            if !set.insert(n) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate nullifier in NullifierSet",
                ));
            }
        }

        Ok(Self(set))
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct V02State {
    public_state: HashMap<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
    programs: HashMap<ProgramId, Program>,
}

impl V02State {
    pub fn new_with_genesis_accounts(
        initial_data: &[(AccountId, u128)],
        initial_commitments: &[nssa_core::Commitment],
    ) -> Self {
        let authenticated_transfer_program = Program::authenticated_transfer_program();
        let public_state = initial_data
            .iter()
            .copied()
            .map(|(account_id, balance)| {
                let account = Account {
                    balance,
                    program_owner: authenticated_transfer_program.id(),
                    ..Account::default()
                };
                (account_id, account)
            })
            .collect();

        let mut private_state = CommitmentSet::with_capacity(32);
        private_state.extend(&[DUMMY_COMMITMENT]);
        private_state.extend(initial_commitments);

        let mut this = Self {
            public_state,
            private_state: (private_state, NullifierSet::new()),
            programs: HashMap::new(),
        };

        this.insert_program(Program::authenticated_transfer_program());
        this.insert_program(Program::token());
        this.insert_program(Program::amm());

        this
    }

    pub(crate) fn insert_program(&mut self, program: Program) {
        self.programs.insert(program.id(), program);
    }

    pub fn transition_from_public_transaction(
        &mut self,
        tx: &PublicTransaction,
    ) -> Result<(), NssaError> {
        let state_diff = tx.validate_and_produce_public_state_diff(self)?;

        for (account_id, post) in state_diff.into_iter() {
            let current_account = self.get_account_by_id_mut(account_id);

            *current_account = post;
        }

        for account_id in tx.signer_account_ids() {
            let current_account = self.get_account_by_id_mut(account_id);
            current_account.nonce += 1;
        }

        Ok(())
    }

    pub fn transition_from_privacy_preserving_transaction(
        &mut self,
        tx: &PrivacyPreservingTransaction,
    ) -> Result<(), NssaError> {
        // 1. Verify the transaction satisfies acceptance criteria
        let public_state_diff = tx.validate_and_produce_public_state_diff(self)?;

        let message = tx.message();

        // 2. Add new commitments
        self.private_state.0.extend(&message.new_commitments);

        // 3. Add new nullifiers
        let new_nullifiers = message
            .new_nullifiers
            .iter()
            .cloned()
            .map(|(nullifier, _)| nullifier)
            .collect::<Vec<Nullifier>>();
        self.private_state.1.extend(new_nullifiers);

        // 4. Update public accounts
        for (account_id, post) in public_state_diff.into_iter() {
            let current_account = self.get_account_by_id_mut(account_id);
            *current_account = post;
        }

        // 5. Increment nonces for public signers
        for account_id in tx.signer_account_ids() {
            let current_account = self.get_account_by_id_mut(account_id);
            current_account.nonce += 1;
        }

        Ok(())
    }

    pub fn transition_from_program_deployment_transaction(
        &mut self,
        tx: &ProgramDeploymentTransaction,
    ) -> Result<(), NssaError> {
        let program = tx.validate_and_produce_public_state_diff(self)?;
        self.insert_program(program);
        Ok(())
    }

    fn get_account_by_id_mut(&mut self, account_id: AccountId) -> &mut Account {
        self.public_state.entry(account_id).or_default()
    }

    pub fn get_account_by_id(&self, account_id: AccountId) -> Account {
        self.public_state
            .get(&account_id)
            .cloned()
            .unwrap_or(Account::default())
    }

    pub fn get_proof_for_commitment(&self, commitment: &Commitment) -> Option<MembershipProof> {
        self.private_state.0.get_proof_for(commitment)
    }

    pub(crate) fn programs(&self) -> &HashMap<ProgramId, Program> {
        &self.programs
    }

    pub fn commitment_set_digest(&self) -> CommitmentSetDigest {
        self.private_state.0.digest()
    }

    pub(crate) fn check_commitments_are_new(
        &self,
        new_commitments: &[Commitment],
    ) -> Result<(), NssaError> {
        for commitment in new_commitments.iter() {
            if self.private_state.0.contains(commitment) {
                return Err(NssaError::InvalidInput(
                    "Commitment already seen".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn check_nullifiers_are_valid(
        &self,
        new_nullifiers: &[(Nullifier, CommitmentSetDigest)],
    ) -> Result<(), NssaError> {
        for (nullifier, digest) in new_nullifiers.iter() {
            if self.private_state.1.contains(nullifier) {
                return Err(NssaError::InvalidInput(
                    "Nullifier already seen".to_string(),
                ));
            }
            if !self.private_state.0.root_history.contains(digest) {
                return Err(NssaError::InvalidInput(
                    "Unrecognized commitment set digest".to_string(),
                ));
            }
        }
        Ok(())
    }
}

// TODO: Testnet only. Refactor to prevent compilation on mainnet.
impl V02State {
    pub fn add_pinata_program(&mut self, account_id: AccountId) {
        self.insert_program(Program::pinata());

        self.public_state.insert(
            account_id,
            Account {
                program_owner: Program::pinata().id(),
                balance: 1500000,
                // Difficulty: 3
                data: vec![3; 33].try_into().expect("should fit"),
                nonce: 0,
            },
        );
    }

    pub fn add_pinata_token_program(&mut self, account_id: AccountId) {
        self.insert_program(Program::pinata_token());

        self.public_state.insert(
            account_id,
            Account {
                program_owner: Program::pinata_token().id(),
                // Difficulty: 3
                data: vec![3; 33].try_into().expect("should fit"),
                ..Account::default()
            },
        );
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl V02State {
    pub fn force_insert_account(&mut self, account_id: AccountId, account: Account) {
        self.public_state.insert(account_id, account);
    }
}

#[cfg(test)]
pub mod tests {

    use std::collections::HashMap;

    use nssa_core::{
        Commitment, Nullifier, NullifierPublicKey, NullifierSecretKey, SharedSecretKey,
        account::{Account, AccountId, AccountWithMetadata, Nonce, data::Data},
        encryption::{EphemeralPublicKey, Scalar, ViewingPublicKey},
        program::{PdaSeed, ProgramId},
    };

    use crate::{
        PublicKey, PublicTransaction, V02State,
        error::NssaError,
        execute_and_prove,
        privacy_preserving_transaction::{
            PrivacyPreservingTransaction,
            circuit::{self, ProgramWithDependencies},
            message::Message,
            witness_set::WitnessSet,
        },
        program::Program,
        public_transaction,
        signature::PrivateKey,
        state::MAX_NUMBER_CHAINED_CALLS,
    };

    fn transfer_transaction(
        from: AccountId,
        from_key: PrivateKey,
        nonce: u128,
        to: AccountId,
        balance: u128,
    ) -> PublicTransaction {
        let account_ids = vec![from, to];
        let nonces = vec![nonce];
        let program_id = Program::authenticated_transfer_program().id();
        let message =
            public_transaction::Message::try_new(program_id, account_ids, nonces, balance).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
        PublicTransaction::new(message, witness_set)
    }

    #[test]
    fn test_new_with_genesis() {
        let key1 = PrivateKey::try_new([1; 32]).unwrap();
        let key2 = PrivateKey::try_new([2; 32]).unwrap();
        let addr1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
        let addr2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
        let initial_data = [(addr1, 100u128), (addr2, 151u128)];
        let authenticated_transfers_program = Program::authenticated_transfer_program();
        let expected_public_state = {
            let mut this = HashMap::new();
            this.insert(
                addr1,
                Account {
                    balance: 100,
                    program_owner: authenticated_transfers_program.id(),
                    ..Account::default()
                },
            );
            this.insert(
                addr2,
                Account {
                    balance: 151,
                    program_owner: authenticated_transfers_program.id(),
                    ..Account::default()
                },
            );
            this
        };
        let expected_builtin_programs = {
            let mut this = HashMap::new();
            this.insert(
                authenticated_transfers_program.id(),
                authenticated_transfers_program,
            );
            this.insert(Program::token().id(), Program::token());
            this.insert(Program::amm().id(), Program::amm());
            this
        };

        let state = V02State::new_with_genesis_accounts(&initial_data, &[]);

        assert_eq!(state.public_state, expected_public_state);
        assert_eq!(state.programs, expected_builtin_programs);
    }

    #[test]
    fn test_insert_program() {
        let mut state = V02State::new_with_genesis_accounts(&[], &[]);
        let program_to_insert = Program::simple_balance_transfer();
        let program_id = program_to_insert.id();
        assert!(!state.programs.contains_key(&program_id));

        state.insert_program(program_to_insert);

        assert!(state.programs.contains_key(&program_id));
    }

    #[test]
    fn test_get_account_by_account_id_non_default_account() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
        let initial_data = [(account_id, 100u128)];
        let state = V02State::new_with_genesis_accounts(&initial_data, &[]);
        let expected_account = state.public_state.get(&account_id).unwrap();

        let account = state.get_account_by_id(account_id);

        assert_eq!(&account, expected_account);
    }

    #[test]
    fn test_get_account_by_account_id_default_account() {
        let addr2 = AccountId::new([0; 32]);
        let state = V02State::new_with_genesis_accounts(&[], &[]);
        let expected_account = Account::default();

        let account = state.get_account_by_id(addr2);

        assert_eq!(account, expected_account);
    }

    #[test]
    fn test_builtin_programs_getter() {
        let state = V02State::new_with_genesis_accounts(&[], &[]);

        let builtin_programs = state.programs();

        assert_eq!(builtin_programs, &state.programs);
    }

    #[test]
    fn transition_from_authenticated_transfer_program_invocation_default_account_destination() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
        let initial_data = [(account_id, 100)];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[]);
        let from = account_id;
        let to = AccountId::new([2; 32]);
        assert_eq!(state.get_account_by_id(to), Account::default());
        let balance_to_move = 5;

        let tx = transfer_transaction(from, key, 0, to, balance_to_move);
        state.transition_from_public_transaction(&tx).unwrap();

        assert_eq!(state.get_account_by_id(from).balance, 95);
        assert_eq!(state.get_account_by_id(to).balance, 5);
        assert_eq!(state.get_account_by_id(from).nonce, 1);
        assert_eq!(state.get_account_by_id(to).nonce, 0);
    }

    #[test]
    fn transition_from_authenticated_transfer_program_invocation_insuficient_balance() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
        let initial_data = [(account_id, 100)];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[]);
        let from = account_id;
        let from_key = key;
        let to = AccountId::new([2; 32]);
        let balance_to_move = 101;
        assert!(state.get_account_by_id(from).balance < balance_to_move);

        let tx = transfer_transaction(from, from_key, 0, to, balance_to_move);
        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::ProgramExecutionFailed(_))));
        assert_eq!(state.get_account_by_id(from).balance, 100);
        assert_eq!(state.get_account_by_id(to).balance, 0);
        assert_eq!(state.get_account_by_id(from).nonce, 0);
        assert_eq!(state.get_account_by_id(to).nonce, 0);
    }

    #[test]
    fn transition_from_authenticated_transfer_program_invocation_non_default_account_destination() {
        let key1 = PrivateKey::try_new([1; 32]).unwrap();
        let key2 = PrivateKey::try_new([2; 32]).unwrap();
        let account_id1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
        let account_id2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
        let initial_data = [(account_id1, 100), (account_id2, 200)];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[]);
        let from = account_id2;
        let from_key = key2;
        let to = account_id1;
        assert_ne!(state.get_account_by_id(to), Account::default());
        let balance_to_move = 8;

        let tx = transfer_transaction(from, from_key, 0, to, balance_to_move);
        state.transition_from_public_transaction(&tx).unwrap();

        assert_eq!(state.get_account_by_id(from).balance, 192);
        assert_eq!(state.get_account_by_id(to).balance, 108);
        assert_eq!(state.get_account_by_id(from).nonce, 1);
        assert_eq!(state.get_account_by_id(to).nonce, 0);
    }

    #[test]
    fn transition_from_sequence_of_authenticated_transfer_program_invocations() {
        let key1 = PrivateKey::try_new([8; 32]).unwrap();
        let account_id1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
        let key2 = PrivateKey::try_new([2; 32]).unwrap();
        let account_id2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
        let initial_data = [(account_id1, 100)];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[]);
        let account_id3 = AccountId::new([3; 32]);
        let balance_to_move = 5;

        let tx = transfer_transaction(account_id1, key1, 0, account_id2, balance_to_move);
        state.transition_from_public_transaction(&tx).unwrap();
        let balance_to_move = 3;
        let tx = transfer_transaction(account_id2, key2, 0, account_id3, balance_to_move);
        state.transition_from_public_transaction(&tx).unwrap();

        assert_eq!(state.get_account_by_id(account_id1).balance, 95);
        assert_eq!(state.get_account_by_id(account_id2).balance, 2);
        assert_eq!(state.get_account_by_id(account_id3).balance, 3);
        assert_eq!(state.get_account_by_id(account_id1).nonce, 1);
        assert_eq!(state.get_account_by_id(account_id2).nonce, 1);
        assert_eq!(state.get_account_by_id(account_id3).nonce, 0);
    }

    impl V02State {
        /// Include test programs in the builtin programs map
        pub fn with_test_programs(mut self) -> Self {
            self.insert_program(Program::nonce_changer_program());
            self.insert_program(Program::extra_output_program());
            self.insert_program(Program::missing_output_program());
            self.insert_program(Program::program_owner_changer());
            self.insert_program(Program::simple_balance_transfer());
            self.insert_program(Program::data_changer());
            self.insert_program(Program::minter());
            self.insert_program(Program::burner());
            self.insert_program(Program::chain_caller());
            self.insert_program(Program::amm());
            self.insert_program(Program::claimer());
            self.insert_program(Program::changer_claimer());
            self
        }

        pub fn with_non_default_accounts_but_default_program_owners(mut self) -> Self {
            let account_with_default_values_except_balance = Account {
                balance: 100,
                ..Account::default()
            };
            let account_with_default_values_except_nonce = Account {
                nonce: 37,
                ..Account::default()
            };
            let account_with_default_values_except_data = Account {
                data: vec![0xca, 0xfe].try_into().unwrap(),
                ..Account::default()
            };
            self.force_insert_account(
                AccountId::new([255; 32]),
                account_with_default_values_except_balance,
            );
            self.force_insert_account(
                AccountId::new([254; 32]),
                account_with_default_values_except_nonce,
            );
            self.force_insert_account(
                AccountId::new([253; 32]),
                account_with_default_values_except_data,
            );
            self
        }

        pub fn with_account_owned_by_burner_program(mut self) -> Self {
            let account = Account {
                program_owner: Program::burner().id(),
                balance: 100,
                ..Default::default()
            };
            self.force_insert_account(AccountId::new([252; 32]), account);
            self
        }

        pub fn with_private_account(mut self, keys: &TestPrivateKeys, account: &Account) -> Self {
            let commitment = Commitment::new(&keys.npk(), account);
            self.private_state.0.extend(&[commitment]);
            self
        }
    }

    #[test]
    fn test_program_should_fail_if_modifies_nonces() {
        let initial_data = [(AccountId::new([1; 32]), 100)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_ids = vec![AccountId::new([1; 32])];
        let program_id = Program::nonce_changer_program().id();
        let message =
            public_transaction::Message::try_new(program_id, account_ids, vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_output_accounts_exceed_inputs() {
        let initial_data = [(AccountId::new([1; 32]), 100)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_ids = vec![AccountId::new([1; 32])];
        let program_id = Program::extra_output_program().id();
        let message =
            public_transaction::Message::try_new(program_id, account_ids, vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_with_missing_output_accounts() {
        let initial_data = [(AccountId::new([1; 32]), 100)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_ids = vec![AccountId::new([1; 32]), AccountId::new([2; 32])];
        let program_id = Program::missing_output_program().id();
        let message =
            public_transaction::Message::try_new(program_id, account_ids, vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_modifies_program_owner_with_only_non_default_program_owner() {
        let initial_data = [(AccountId::new([1; 32]), 0)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_id = AccountId::new([1; 32]);
        let account = state.get_account_by_id(account_id);
        // Assert the target account only differs from the default account in the program owner
        // field
        assert_ne!(account.program_owner, Account::default().program_owner);
        assert_eq!(account.balance, Account::default().balance);
        assert_eq!(account.nonce, Account::default().nonce);
        assert_eq!(account.data, Account::default().data);
        let program_id = Program::program_owner_changer().id();
        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_modifies_program_owner_with_only_non_default_balance() {
        let initial_data = [];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[])
            .with_test_programs()
            .with_non_default_accounts_but_default_program_owners();
        let account_id = AccountId::new([255; 32]);
        let account = state.get_account_by_id(account_id);
        // Assert the target account only differs from the default account in balance field
        assert_eq!(account.program_owner, Account::default().program_owner);
        assert_ne!(account.balance, Account::default().balance);
        assert_eq!(account.nonce, Account::default().nonce);
        assert_eq!(account.data, Account::default().data);
        let program_id = Program::program_owner_changer().id();
        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_modifies_program_owner_with_only_non_default_nonce() {
        let initial_data = [];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[])
            .with_test_programs()
            .with_non_default_accounts_but_default_program_owners();
        let account_id = AccountId::new([254; 32]);
        let account = state.get_account_by_id(account_id);
        // Assert the target account only differs from the default account in nonce field
        assert_eq!(account.program_owner, Account::default().program_owner);
        assert_eq!(account.balance, Account::default().balance);
        assert_ne!(account.nonce, Account::default().nonce);
        assert_eq!(account.data, Account::default().data);
        let program_id = Program::program_owner_changer().id();
        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_modifies_program_owner_with_only_non_default_data() {
        let initial_data = [];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[])
            .with_test_programs()
            .with_non_default_accounts_but_default_program_owners();
        let account_id = AccountId::new([253; 32]);
        let account = state.get_account_by_id(account_id);
        // Assert the target account only differs from the default account in data field
        assert_eq!(account.program_owner, Account::default().program_owner);
        assert_eq!(account.balance, Account::default().balance);
        assert_eq!(account.nonce, Account::default().nonce);
        assert_ne!(account.data, Account::default().data);
        let program_id = Program::program_owner_changer().id();
        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_transfers_balance_from_non_owned_account() {
        let initial_data = [(AccountId::new([1; 32]), 100)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let sender_account_id = AccountId::new([1; 32]);
        let receiver_account_id = AccountId::new([2; 32]);
        let balance_to_move: u128 = 1;
        let program_id = Program::simple_balance_transfer().id();
        assert_ne!(
            state.get_account_by_id(sender_account_id).program_owner,
            program_id
        );
        let message = public_transaction::Message::try_new(
            program_id,
            vec![sender_account_id, receiver_account_id],
            vec![],
            balance_to_move,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_modifies_data_of_non_owned_account() {
        let initial_data = [];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[])
            .with_test_programs()
            .with_non_default_accounts_but_default_program_owners();
        let account_id = AccountId::new([255; 32]);
        let program_id = Program::data_changer().id();

        assert_ne!(state.get_account_by_id(account_id), Account::default());
        assert_ne!(
            state.get_account_by_id(account_id).program_owner,
            program_id
        );
        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], vec![0])
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_does_not_preserve_total_balance_by_minting() {
        let initial_data = [];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_id = AccountId::new([1; 32]);
        let program_id = Program::minter().id();

        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_program_should_fail_if_does_not_preserve_total_balance_by_burning() {
        let initial_data = [];
        let mut state = V02State::new_with_genesis_accounts(&initial_data, &[])
            .with_test_programs()
            .with_account_owned_by_burner_program();
        let program_id = Program::burner().id();
        let account_id = AccountId::new([252; 32]);
        assert_eq!(
            state.get_account_by_id(account_id).program_owner,
            program_id
        );
        let balance_to_burn: u128 = 1;
        assert!(state.get_account_by_id(account_id).balance > balance_to_burn);

        let message = public_transaction::Message::try_new(
            program_id,
            vec![account_id],
            vec![],
            balance_to_burn,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);
        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    pub struct TestPublicKeys {
        pub signing_key: PrivateKey,
    }

    impl TestPublicKeys {
        pub fn account_id(&self) -> AccountId {
            AccountId::from(&PublicKey::new_from_private_key(&self.signing_key))
        }
    }

    fn test_public_account_keys_1() -> TestPublicKeys {
        TestPublicKeys {
            signing_key: PrivateKey::try_new([37; 32]).unwrap(),
        }
    }

    pub struct TestPrivateKeys {
        pub nsk: NullifierSecretKey,
        pub vsk: Scalar,
    }

    impl TestPrivateKeys {
        pub fn npk(&self) -> NullifierPublicKey {
            NullifierPublicKey::from(&self.nsk)
        }

        pub fn vpk(&self) -> ViewingPublicKey {
            ViewingPublicKey::from_scalar(self.vsk)
        }
    }

    pub fn test_private_account_keys_1() -> TestPrivateKeys {
        TestPrivateKeys {
            nsk: [13; 32],
            vsk: [31; 32],
        }
    }

    pub fn test_private_account_keys_2() -> TestPrivateKeys {
        TestPrivateKeys {
            nsk: [38; 32],
            vsk: [83; 32],
        }
    }

    fn shielded_balance_transfer_for_tests(
        sender_keys: &TestPublicKeys,
        recipient_keys: &TestPrivateKeys,
        balance_to_move: u128,
        state: &V02State,
    ) -> PrivacyPreservingTransaction {
        let sender = AccountWithMetadata::new(
            state.get_account_by_id(sender_keys.account_id()),
            true,
            sender_keys.account_id(),
        );

        let sender_nonce = sender.account.nonce;

        let recipient = AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &recipient_keys.vpk());
        let epk = EphemeralPublicKey::from_scalar(esk);

        let (output, proof) = circuit::execute_and_prove(
            vec![sender, recipient],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![0, 2],
            vec![0xdeadbeef],
            vec![(recipient_keys.npk(), shared_secret)],
            vec![],
            vec![None],
            &Program::authenticated_transfer_program().into(),
        )
        .unwrap();

        let message = Message::try_from_circuit_output(
            vec![sender_keys.account_id()],
            vec![sender_nonce],
            vec![(recipient_keys.npk(), recipient_keys.vpk(), epk)],
            output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[&sender_keys.signing_key]);
        PrivacyPreservingTransaction::new(message, witness_set)
    }

    fn private_balance_transfer_for_tests(
        sender_keys: &TestPrivateKeys,
        sender_private_account: &Account,
        recipient_keys: &TestPrivateKeys,
        balance_to_move: u128,
        new_nonces: [Nonce; 2],
        state: &V02State,
    ) -> PrivacyPreservingTransaction {
        let program = Program::authenticated_transfer_program();
        let sender_commitment = Commitment::new(&sender_keys.npk(), sender_private_account);
        let sender_pre =
            AccountWithMetadata::new(sender_private_account.clone(), true, &sender_keys.npk());
        let recipient_pre =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        let esk_1 = [3; 32];
        let shared_secret_1 = SharedSecretKey::new(&esk_1, &sender_keys.vpk());
        let epk_1 = EphemeralPublicKey::from_scalar(esk_1);

        let esk_2 = [3; 32];
        let shared_secret_2 = SharedSecretKey::new(&esk_2, &recipient_keys.vpk());
        let epk_2 = EphemeralPublicKey::from_scalar(esk_2);

        let (output, proof) = circuit::execute_and_prove(
            vec![sender_pre, recipient_pre],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![1, 2],
            new_nonces.to_vec(),
            vec![
                (sender_keys.npk(), shared_secret_1),
                (recipient_keys.npk(), shared_secret_2),
            ],
            vec![sender_keys.nsk],
            vec![state.get_proof_for_commitment(&sender_commitment), None],
            &program.into(),
        )
        .unwrap();

        let message = Message::try_from_circuit_output(
            vec![],
            vec![],
            vec![
                (sender_keys.npk(), sender_keys.vpk(), epk_1),
                (recipient_keys.npk(), recipient_keys.vpk(), epk_2),
            ],
            output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]);

        PrivacyPreservingTransaction::new(message, witness_set)
    }

    fn deshielded_balance_transfer_for_tests(
        sender_keys: &TestPrivateKeys,
        sender_private_account: &Account,
        recipient_account_id: &AccountId,
        balance_to_move: u128,
        new_nonce: Nonce,
        state: &V02State,
    ) -> PrivacyPreservingTransaction {
        let program = Program::authenticated_transfer_program();
        let sender_commitment = Commitment::new(&sender_keys.npk(), sender_private_account);
        let sender_pre =
            AccountWithMetadata::new(sender_private_account.clone(), true, &sender_keys.npk());
        let recipient_pre = AccountWithMetadata::new(
            state.get_account_by_id(*recipient_account_id),
            false,
            *recipient_account_id,
        );

        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &sender_keys.vpk());
        let epk = EphemeralPublicKey::from_scalar(esk);

        let (output, proof) = circuit::execute_and_prove(
            vec![sender_pre, recipient_pre],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![1, 0],
            vec![new_nonce],
            vec![(sender_keys.npk(), shared_secret)],
            vec![sender_keys.nsk],
            vec![state.get_proof_for_commitment(&sender_commitment)],
            &program.into(),
        )
        .unwrap();

        let message = Message::try_from_circuit_output(
            vec![*recipient_account_id],
            vec![],
            vec![(sender_keys.npk(), sender_keys.vpk(), epk)],
            output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]);

        PrivacyPreservingTransaction::new(message, witness_set)
    }

    #[test]
    fn test_transition_from_privacy_preserving_transaction_shielded() {
        let sender_keys = test_public_account_keys_1();
        let recipient_keys = test_private_account_keys_1();

        let mut state =
            V02State::new_with_genesis_accounts(&[(sender_keys.account_id(), 200)], &[]);

        let balance_to_move = 37;

        let tx = shielded_balance_transfer_for_tests(
            &sender_keys,
            &recipient_keys,
            balance_to_move,
            &state,
        );

        let expected_sender_post = {
            let mut this = state.get_account_by_id(sender_keys.account_id());
            this.balance -= balance_to_move;
            this.nonce += 1;
            this
        };

        let [expected_new_commitment] = tx.message().new_commitments.clone().try_into().unwrap();
        assert!(!state.private_state.0.contains(&expected_new_commitment));

        state
            .transition_from_privacy_preserving_transaction(&tx)
            .unwrap();

        let sender_post = state.get_account_by_id(sender_keys.account_id());
        assert_eq!(sender_post, expected_sender_post);
        assert!(state.private_state.0.contains(&expected_new_commitment));

        assert_eq!(
            state.get_account_by_id(sender_keys.account_id()).balance,
            200 - balance_to_move
        );
    }

    #[test]
    fn test_transition_from_privacy_preserving_transaction_private() {
        let sender_keys = test_private_account_keys_1();
        let sender_private_account = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: 100,
            nonce: 0xdeadbeef,
            data: Data::default(),
        };
        let recipient_keys = test_private_account_keys_2();

        let mut state = V02State::new_with_genesis_accounts(&[], &[])
            .with_private_account(&sender_keys, &sender_private_account);

        let balance_to_move = 37;

        let tx = private_balance_transfer_for_tests(
            &sender_keys,
            &sender_private_account,
            &recipient_keys,
            balance_to_move,
            [0xcafecafe, 0xfecafeca],
            &state,
        );

        let expected_new_commitment_1 = Commitment::new(
            &sender_keys.npk(),
            &Account {
                program_owner: Program::authenticated_transfer_program().id(),
                nonce: 0xcafecafe,
                balance: sender_private_account.balance - balance_to_move,
                data: Data::default(),
            },
        );

        let sender_pre_commitment = Commitment::new(&sender_keys.npk(), &sender_private_account);
        let expected_new_nullifier =
            Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk);

        let expected_new_commitment_2 = Commitment::new(
            &recipient_keys.npk(),
            &Account {
                program_owner: Program::authenticated_transfer_program().id(),
                nonce: 0xfecafeca,
                balance: balance_to_move,
                ..Account::default()
            },
        );

        let previous_public_state = state.public_state.clone();
        assert!(state.private_state.0.contains(&sender_pre_commitment));
        assert!(!state.private_state.0.contains(&expected_new_commitment_1));
        assert!(!state.private_state.0.contains(&expected_new_commitment_2));
        assert!(!state.private_state.1.contains(&expected_new_nullifier));

        state
            .transition_from_privacy_preserving_transaction(&tx)
            .unwrap();

        assert_eq!(state.public_state, previous_public_state);
        assert!(state.private_state.0.contains(&sender_pre_commitment));
        assert!(state.private_state.0.contains(&expected_new_commitment_1));
        assert!(state.private_state.0.contains(&expected_new_commitment_2));
        assert!(state.private_state.1.contains(&expected_new_nullifier));
    }

    #[test]
    fn test_transition_from_privacy_preserving_transaction_deshielded() {
        let sender_keys = test_private_account_keys_1();
        let sender_private_account = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: 100,
            nonce: 0xdeadbeef,
            data: Data::default(),
        };
        let recipient_keys = test_public_account_keys_1();
        let recipient_initial_balance = 400;
        let mut state = V02State::new_with_genesis_accounts(
            &[(recipient_keys.account_id(), recipient_initial_balance)],
            &[],
        )
        .with_private_account(&sender_keys, &sender_private_account);

        let balance_to_move = 37;

        let expected_recipient_post = {
            let mut this = state.get_account_by_id(recipient_keys.account_id());
            this.balance += balance_to_move;
            this
        };

        let tx = deshielded_balance_transfer_for_tests(
            &sender_keys,
            &sender_private_account,
            &recipient_keys.account_id(),
            balance_to_move,
            0xcafecafe,
            &state,
        );

        let expected_new_commitment = Commitment::new(
            &sender_keys.npk(),
            &Account {
                program_owner: Program::authenticated_transfer_program().id(),
                nonce: 0xcafecafe,
                balance: sender_private_account.balance - balance_to_move,
                data: Data::default(),
            },
        );

        let sender_pre_commitment = Commitment::new(&sender_keys.npk(), &sender_private_account);
        let expected_new_nullifier =
            Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk);

        assert!(state.private_state.0.contains(&sender_pre_commitment));
        assert!(!state.private_state.0.contains(&expected_new_commitment));
        assert!(!state.private_state.1.contains(&expected_new_nullifier));

        state
            .transition_from_privacy_preserving_transaction(&tx)
            .unwrap();

        let recipient_post = state.get_account_by_id(recipient_keys.account_id());
        assert_eq!(recipient_post, expected_recipient_post);
        assert!(state.private_state.0.contains(&sender_pre_commitment));
        assert!(state.private_state.0.contains(&expected_new_commitment));
        assert!(state.private_state.1.contains(&expected_new_nullifier));
        assert_eq!(
            state.get_account_by_id(recipient_keys.account_id()).balance,
            recipient_initial_balance + balance_to_move
        );
    }

    #[test]
    fn test_burner_program_should_fail_in_privacy_preserving_circuit() {
        let program = Program::burner();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(10u128).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_minter_program_should_fail_in_privacy_preserving_circuit() {
        let program = Program::minter();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(10u128).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_nonce_changer_program_should_fail_in_privacy_preserving_circuit() {
        let program = Program::nonce_changer_program();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(()).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_data_changer_program_should_fail_for_non_owned_account_in_privacy_preserving_circuit() {
        let program = Program::data_changer();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: [0, 1, 2, 3, 4, 5, 6, 7],
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(vec![0]).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_data_changer_program_should_fail_for_too_large_data_in_privacy_preserving_circuit() {
        let program = Program::data_changer();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let large_data: Vec<u8> =
            vec![0; nssa_core::account::data::DATA_MAX_LENGTH.as_u64() as usize + 1];

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(large_data).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.to_owned().into(),
        );

        assert!(matches!(result, Err(NssaError::ProgramProveFailed(_))));
    }

    #[test]
    fn test_extra_output_program_should_fail_in_privacy_preserving_circuit() {
        let program = Program::extra_output_program();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(()).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_missing_output_program_should_fail_in_privacy_preserving_circuit() {
        let program = Program::missing_output_program();
        let public_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );
        let public_account_2 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([1; 32]),
        );

        let result = execute_and_prove(
            vec![public_account_1, public_account_2],
            Program::serialize_instruction(()).unwrap(),
            vec![0, 0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_program_owner_changer_should_fail_in_privacy_preserving_circuit() {
        let program = Program::program_owner_changer();
        let public_account = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let result = execute_and_prove(
            vec![public_account],
            Program::serialize_instruction(()).unwrap(),
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_transfer_from_non_owned_account_should_fail_in_privacy_preserving_circuit() {
        let program = Program::simple_balance_transfer();
        let public_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: [0, 1, 2, 3, 4, 5, 6, 7],
                balance: 100,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );
        let public_account_2 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([1; 32]),
        );

        let result = execute_and_prove(
            vec![public_account_1, public_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![0, 0],
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_fails_if_visibility_masks_have_incorrect_lenght() {
        let program = Program::simple_balance_transfer();
        let public_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );
        let public_account_2 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 0,
                ..Account::default()
            },
            true,
            AccountId::new([1; 32]),
        );

        // Setting only one visibility mask for a circuit execution with two pre_state accounts.
        let visibility_mask = [0];
        let result = execute_and_prove(
            vec![public_account_1, public_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            visibility_mask.to_vec(),
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_fails_if_insufficient_nonces_are_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        // Setting only one nonce for an execution with two private accounts.
        let private_account_nonces = [0xdeadbeef1];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            private_account_nonces.to_vec(),
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_fails_if_insufficient_keys_are_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, AccountId::new([1; 32]));

        // Setting only one key for an execution with two private accounts.
        let private_account_keys = [(
            sender_keys.npk(),
            SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
        )];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            private_account_keys.to_vec(),
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_fails_if_insufficient_commitment_proofs_are_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        // Setting no second commitment proof.
        let private_account_membership_proofs = [Some((0, vec![]))];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            private_account_membership_proofs.to_vec(),
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_fails_if_insufficient_auth_keys_are_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        // Setting no auth key for an execution with one non default private accounts.
        let private_account_nsks = [];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            private_account_nsks.to_vec(),
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_fails_if_invalid_auth_keys_are_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        let private_account_keys = [
            // First private account is the sender
            (
                sender_keys.npk(),
                SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
            ),
            // Second private account is the recipient
            (
                recipient_keys.npk(),
                SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
            ),
        ];

        // Setting the recipient key to authorize the sender.
        // This should be set to the sender private account in
        // a normal circumstance. The recipient can't authorize this.
        let private_account_nsks = [recipient_keys.nsk];
        let private_account_membership_proofs = [Some((0, vec![]))];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            private_account_keys.to_vec(),
            private_account_nsks.to_vec(),
            private_account_membership_proofs.to_vec(),
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_if_new_private_account_with_non_default_balance_is_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 = AccountWithMetadata::new(
            Account {
                // Non default balance
                balance: 1,
                ..Account::default()
            },
            false,
            &recipient_keys.npk(),
        );

        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_if_new_private_account_with_non_default_program_owner_is_provided()
    {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 = AccountWithMetadata::new(
            Account {
                // Non default program_owner
                program_owner: [0, 1, 2, 3, 4, 5, 6, 7],
                ..Account::default()
            },
            false,
            &recipient_keys.npk(),
        );

        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_if_new_private_account_with_non_default_data_is_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 = AccountWithMetadata::new(
            Account {
                // Non default data
                data: b"hola mundo".to_vec().try_into().unwrap(),
                ..Account::default()
            },
            false,
            &recipient_keys.npk(),
        );

        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_if_new_private_account_with_non_default_nonce_is_provided() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 = AccountWithMetadata::new(
            Account {
                // Non default nonce
                nonce: 0xdeadbeef,
                ..Account::default()
            },
            false,
            &recipient_keys.npk(),
        );

        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_if_new_private_account_is_provided_with_default_values_but_marked_as_authorized()
     {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 = AccountWithMetadata::new(
            Account::default(),
            // This should be set to false in normal circumstances
            true,
            &recipient_keys.npk(),
        );

        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_with_invalid_visibility_mask_value() {
        let program = Program::simple_balance_transfer();
        let public_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );
        let public_account_2 =
            AccountWithMetadata::new(Account::default(), false, AccountId::new([1; 32]));

        let visibility_mask = [0, 3];
        let result = execute_and_prove(
            vec![public_account_1, public_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            visibility_mask.to_vec(),
            vec![],
            vec![],
            vec![],
            vec![],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_with_too_many_nonces() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        // Setting three new private account nonces for a circuit execution with only two private
        // accounts.
        let private_account_nonces = [0xdeadbeef1, 0xdeadbeef2, 0xdeadbeef3];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            private_account_nonces.to_vec(),
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_with_too_many_private_account_keys() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        // Setting three private account keys for a circuit execution with only two private
        // accounts.
        let private_account_keys = [
            (
                sender_keys.npk(),
                SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
            ),
            (
                recipient_keys.npk(),
                SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
            ),
            (
                sender_keys.npk(),
                SharedSecretKey::new(&[57; 32], &sender_keys.vpk()),
            ),
        ];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            vec![1, 2],
            vec![0xdeadbeef1, 0xdeadbeef2],
            private_account_keys.to_vec(),
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_circuit_should_fail_with_too_many_private_account_auth_keys() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );
        let private_account_2 =
            AccountWithMetadata::new(Account::default(), false, &recipient_keys.npk());

        // Setting two private account keys for a circuit execution with only one non default
        // private account (visibility mask equal to 1 means that auth keys are expected).
        let visibility_mask = [1, 2];
        let private_account_nsks = [sender_keys.nsk, recipient_keys.nsk];
        let private_account_membership_proofs = [Some((0, vec![])), Some((1, vec![]))];
        let result = execute_and_prove(
            vec![private_account_1, private_account_2],
            Program::serialize_instruction(10u128).unwrap(),
            visibility_mask.to_vec(),
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (
                    sender_keys.npk(),
                    SharedSecretKey::new(&[55; 32], &sender_keys.vpk()),
                ),
                (
                    recipient_keys.npk(),
                    SharedSecretKey::new(&[56; 32], &recipient_keys.vpk()),
                ),
            ],
            private_account_nsks.to_vec(),
            private_account_membership_proofs.to_vec(),
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_private_accounts_can_only_be_initialized_once() {
        let sender_keys = test_private_account_keys_1();
        let sender_private_account = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: 100,
            nonce: 0xdeadbeef,
            data: Data::default(),
        };
        let recipient_keys = test_private_account_keys_2();

        let mut state = V02State::new_with_genesis_accounts(&[], &[])
            .with_private_account(&sender_keys, &sender_private_account);

        let balance_to_move = 37;

        let tx = private_balance_transfer_for_tests(
            &sender_keys,
            &sender_private_account,
            &recipient_keys,
            balance_to_move,
            [0xcafecafe, 0xfecafeca],
            &state,
        );

        state
            .transition_from_privacy_preserving_transaction(&tx)
            .unwrap();

        let sender_private_account = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: 100 - balance_to_move,
            nonce: 0xcafecafe,
            data: Data::default(),
        };

        let tx = private_balance_transfer_for_tests(
            &sender_keys,
            &sender_private_account,
            &recipient_keys,
            balance_to_move,
            [0x1234, 0x5678],
            &state,
        );

        let result = state.transition_from_privacy_preserving_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidInput(_))));
        let NssaError::InvalidInput(error_message) = result.err().unwrap() else {
            panic!("Incorrect message error");
        };
        let expected_error_message = "Nullifier already seen".to_string();
        assert_eq!(error_message, expected_error_message);
    }

    #[test]
    fn test_circuit_should_fail_if_there_are_repeated_ids() {
        let program = Program::simple_balance_transfer();
        let sender_keys = test_private_account_keys_1();
        let private_account_1 = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            &sender_keys.npk(),
        );

        let visibility_mask = [1, 1];
        let private_account_nsks = [sender_keys.nsk, sender_keys.nsk];
        let private_account_membership_proofs = [Some((1, vec![])), Some((1, vec![]))];
        let shared_secret = SharedSecretKey::new(&[55; 32], &sender_keys.vpk());
        let result = execute_and_prove(
            vec![private_account_1.clone(), private_account_1],
            Program::serialize_instruction(100u128).unwrap(),
            visibility_mask.to_vec(),
            vec![0xdeadbeef1, 0xdeadbeef2],
            vec![
                (sender_keys.npk(), shared_secret),
                (sender_keys.npk(), shared_secret),
            ],
            private_account_nsks.to_vec(),
            private_account_membership_proofs.to_vec(),
            &program.into(),
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_claiming_mechanism() {
        let program = Program::authenticated_transfer_program();
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
        let initial_balance = 100;
        let initial_data = [(account_id, initial_balance)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let from = account_id;
        let from_key = key;
        let to = AccountId::new([2; 32]);
        let amount: u128 = 37;

        // Check the recipient is an uninitialized account
        assert_eq!(state.get_account_by_id(to), Account::default());

        let expected_recipient_post = Account {
            program_owner: program.id(),
            balance: amount,
            ..Account::default()
        };

        let message =
            public_transaction::Message::try_new(program.id(), vec![from, to], vec![0], amount)
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
        let tx = PublicTransaction::new(message, witness_set);

        state.transition_from_public_transaction(&tx).unwrap();

        let recipient_post = state.get_account_by_id(to);

        assert_eq!(recipient_post, expected_recipient_post);
    }

    #[test]
    fn test_public_chained_call() {
        let program = Program::chain_caller();
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let from = AccountId::from(&PublicKey::new_from_private_key(&key));
        let to = AccountId::new([2; 32]);
        let initial_balance = 1000;
        let initial_data = [(from, initial_balance), (to, 0)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let from_key = key;
        let amount: u128 = 37;
        let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
            amount,
            Program::authenticated_transfer_program().id(),
            2,
            None,
        );

        let expected_to_post = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: amount * 2, // The `chain_caller` chains the program twice
            ..Account::default()
        };

        let message = public_transaction::Message::try_new(
            program.id(),
            vec![to, from], // The chain_caller program permutes the account order in the chain
            // call
            vec![0],
            instruction,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
        let tx = PublicTransaction::new(message, witness_set);

        state.transition_from_public_transaction(&tx).unwrap();

        let from_post = state.get_account_by_id(from);
        let to_post = state.get_account_by_id(to);
        // The `chain_caller` program calls the program twice
        assert_eq!(from_post.balance, initial_balance - 2 * amount);
        assert_eq!(to_post, expected_to_post);
    }

    #[test]
    fn test_execution_fails_if_chained_calls_exceeds_depth() {
        let program = Program::chain_caller();
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let from = AccountId::from(&PublicKey::new_from_private_key(&key));
        let to = AccountId::new([2; 32]);
        let initial_balance = 100;
        let initial_data = [(from, initial_balance), (to, 0)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let from_key = key;
        let amount: u128 = 0;
        let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
            amount,
            Program::authenticated_transfer_program().id(),
            MAX_NUMBER_CHAINED_CALLS as u32 + 1,
            None,
        );

        let message = public_transaction::Message::try_new(
            program.id(),
            vec![to, from], // The chain_caller program permutes the account order in the chain
            // call
            vec![0],
            instruction,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);
        assert!(matches!(
            result,
            Err(NssaError::MaxChainedCallsDepthExceeded)
        ));
    }

    #[test]
    fn test_execution_that_requires_authentication_of_a_program_derived_account_id_succeeds() {
        let chain_caller = Program::chain_caller();
        let pda_seed = PdaSeed::new([37; 32]);
        let from = AccountId::from((&chain_caller.id(), &pda_seed));
        let to = AccountId::new([2; 32]);
        let initial_balance = 1000;
        let initial_data = [(from, initial_balance), (to, 0)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let amount: u128 = 58;
        let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
            amount,
            Program::authenticated_transfer_program().id(),
            1,
            Some(pda_seed),
        );

        let expected_to_post = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: amount, // The `chain_caller` chains the program twice
            ..Account::default()
        };
        let message = public_transaction::Message::try_new(
            chain_caller.id(),
            vec![to, from], // The chain_caller program permutes the account order in the chain
            // call
            vec![],
            instruction,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        state.transition_from_public_transaction(&tx).unwrap();

        let from_post = state.get_account_by_id(from);
        let to_post = state.get_account_by_id(to);
        assert_eq!(from_post.balance, initial_balance - amount);
        assert_eq!(to_post, expected_to_post);
    }

    #[test]
    fn test_claiming_mechanism_within_chain_call() {
        // This test calls the authenticated transfer program through the chain_caller program.
        // The transfer is made from an initialized sender to an uninitialized recipient. And
        // it is expected that the recipient account is claimed by the authenticated transfer
        // program and not the chained_caller program.
        let chain_caller = Program::chain_caller();
        let auth_transfer = Program::authenticated_transfer_program();
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
        let initial_balance = 100;
        let initial_data = [(account_id, initial_balance)];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let from = account_id;
        let from_key = key;
        let to = AccountId::new([2; 32]);
        let amount: u128 = 37;

        // Check the recipient is an uninitialized account
        assert_eq!(state.get_account_by_id(to), Account::default());

        let expected_to_post = Account {
            // The expected program owner is the authenticated transfer program
            program_owner: auth_transfer.id(),
            balance: amount,
            ..Account::default()
        };

        // The transaction executes the chain_caller program, which internally calls the
        // authenticated_transfer program
        let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
            amount,
            Program::authenticated_transfer_program().id(),
            1,
            None,
        );
        let message = public_transaction::Message::try_new(
            chain_caller.id(),
            vec![to, from], // The chain_caller program permutes the account order in the chain
            // call
            vec![0],
            instruction,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
        let tx = PublicTransaction::new(message, witness_set);

        state.transition_from_public_transaction(&tx).unwrap();

        let from_post = state.get_account_by_id(from);
        let to_post = state.get_account_by_id(to);
        assert_eq!(from_post.balance, initial_balance - amount);
        assert_eq!(to_post, expected_to_post);
    }

    #[test_case::test_case(1; "single call")]
    #[test_case::test_case(2; "two calls")]
    fn test_private_chained_call(number_of_calls: u32) {
        // Arrange
        let chain_caller = Program::chain_caller();
        let auth_transfers = Program::authenticated_transfer_program();
        let from_keys = test_private_account_keys_1();
        let to_keys = test_private_account_keys_2();
        let initial_balance = 100;
        let from_account = AccountWithMetadata::new(
            Account {
                program_owner: auth_transfers.id(),
                balance: initial_balance,
                ..Account::default()
            },
            true,
            &from_keys.npk(),
        );
        let to_account = AccountWithMetadata::new(
            Account {
                program_owner: auth_transfers.id(),
                ..Account::default()
            },
            true,
            &to_keys.npk(),
        );

        let from_commitment = Commitment::new(&from_keys.npk(), &from_account.account);
        let to_commitment = Commitment::new(&to_keys.npk(), &to_account.account);
        let mut state = V02State::new_with_genesis_accounts(
            &[],
            &[from_commitment.clone(), to_commitment.clone()],
        )
        .with_test_programs();
        let amount: u128 = 37;
        let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
            amount,
            Program::authenticated_transfer_program().id(),
            number_of_calls,
            None,
        );

        let from_esk = [3; 32];
        let from_ss = SharedSecretKey::new(&from_esk, &from_keys.vpk());
        let from_epk = EphemeralPublicKey::from_scalar(from_esk);

        let to_esk = [3; 32];
        let to_ss = SharedSecretKey::new(&to_esk, &to_keys.vpk());
        let to_epk = EphemeralPublicKey::from_scalar(to_esk);

        let mut dependencies = HashMap::new();

        dependencies.insert(auth_transfers.id(), auth_transfers);
        let program_with_deps = ProgramWithDependencies::new(chain_caller, dependencies);

        let from_new_nonce = 0xdeadbeef1;
        let to_new_nonce = 0xdeadbeef2;

        let from_expected_post = Account {
            balance: initial_balance - number_of_calls as u128 * amount,
            nonce: from_new_nonce,
            ..from_account.account.clone()
        };
        let from_expected_commitment = Commitment::new(&from_keys.npk(), &from_expected_post);

        let to_expected_post = Account {
            balance: number_of_calls as u128 * amount,
            nonce: to_new_nonce,
            ..to_account.account.clone()
        };
        let to_expected_commitment = Commitment::new(&to_keys.npk(), &to_expected_post);

        // Act
        let (output, proof) = execute_and_prove(
            vec![to_account, from_account],
            Program::serialize_instruction(instruction).unwrap(),
            vec![1, 1],
            vec![from_new_nonce, to_new_nonce],
            vec![(from_keys.npk(), to_ss), (to_keys.npk(), from_ss)],
            vec![from_keys.nsk, to_keys.nsk],
            vec![
                state.get_proof_for_commitment(&from_commitment),
                state.get_proof_for_commitment(&to_commitment),
            ],
            &program_with_deps,
        )
        .unwrap();

        let message = Message::try_from_circuit_output(
            vec![],
            vec![],
            vec![
                (to_keys.npk(), to_keys.vpk(), to_epk),
                (from_keys.npk(), from_keys.vpk(), from_epk),
            ],
            output,
        )
        .unwrap();
        let witness_set = WitnessSet::for_message(&message, proof, &[]);
        let transaction = PrivacyPreservingTransaction::new(message, witness_set);

        state
            .transition_from_privacy_preserving_transaction(&transaction)
            .unwrap();

        // Assert
        assert!(
            state
                .get_proof_for_commitment(&from_expected_commitment)
                .is_some()
        );
        assert!(
            state
                .get_proof_for_commitment(&to_expected_commitment)
                .is_some()
        );
    }

    #[test]
    fn test_pda_mechanism_with_pinata_token_program() {
        let pinata_token = Program::pinata_token();
        let token = Program::token();

        let pinata_definition_id = AccountId::new([1; 32]);
        let pinata_token_definition_id = AccountId::new([2; 32]);
        // Total supply of pinata token will be in an account under a PDA.
        let pinata_token_holding_id = AccountId::from((&pinata_token.id(), &PdaSeed::new([0; 32])));
        let winner_token_holding_id = AccountId::new([3; 32]);

        let expected_winner_account_holding = token_core::TokenHolding::Fungible {
            definition_id: pinata_token_definition_id,
            balance: 150,
        };
        let expected_winner_token_holding_post = Account {
            program_owner: token.id(),
            data: Data::from(&expected_winner_account_holding),
            ..Account::default()
        };

        let mut state = V02State::new_with_genesis_accounts(&[], &[]);
        state.add_pinata_token_program(pinata_definition_id);

        // Execution of the token program to create new token for the pinata token
        // definition and supply accounts
        let total_supply: u128 = 10_000_000;
        let instruction = token_core::Instruction::NewFungibleDefinition {
            name: String::from("PINATA"),
            total_supply,
        };
        let message = public_transaction::Message::try_new(
            token.id(),
            vec![pinata_token_definition_id, pinata_token_holding_id],
            vec![],
            instruction,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);
        state.transition_from_public_transaction(&tx).unwrap();

        // Execution of winner's token holding account initialization
        let instruction = token_core::Instruction::InitializeAccount;
        let message = public_transaction::Message::try_new(
            token.id(),
            vec![pinata_token_definition_id, winner_token_holding_id],
            vec![],
            instruction,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);
        state.transition_from_public_transaction(&tx).unwrap();

        // Submit a solution to the pinata program to claim the prize
        let solution: u128 = 989106;
        let message = public_transaction::Message::try_new(
            pinata_token.id(),
            vec![
                pinata_definition_id,
                pinata_token_holding_id,
                winner_token_holding_id,
            ],
            vec![],
            solution,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);
        state.transition_from_public_transaction(&tx).unwrap();

        let winner_token_holding_post = state.get_account_by_id(winner_token_holding_id);
        assert_eq!(
            winner_token_holding_post,
            expected_winner_token_holding_post
        );
    }

    #[test]
    fn test_claiming_mechanism_cannot_claim_initialied_accounts() {
        let claimer = Program::claimer();
        let mut state = V02State::new_with_genesis_accounts(&[], &[]).with_test_programs();
        let account_id = AccountId::new([2; 32]);

        // Insert an account with non-default program owner
        state.force_insert_account(
            account_id,
            Account {
                program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
                ..Account::default()
            },
        );

        let message =
            public_transaction::Message::try_new(claimer.id(), vec![account_id], vec![], ())
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)))
    }

    /// This test ensures that even if a malicious program tries to perform overflow of balances
    /// it will not be able to break the balance validation.
    #[test]
    fn test_malicious_program_cannot_break_balance_validation() {
        let sender_key = PrivateKey::try_new([37; 32]).unwrap();
        let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
        let sender_init_balance: u128 = 10;

        let recipient_key = PrivateKey::try_new([42; 32]).unwrap();
        let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
        let recipient_init_balance: u128 = 10;

        let mut state = V02State::new_with_genesis_accounts(
            &[
                (sender_id, sender_init_balance),
                (recipient_id, recipient_init_balance),
            ],
            &[],
        );

        state.insert_program(Program::modified_transfer_program());

        let balance_to_move: u128 = 4;

        let sender = AccountWithMetadata::new(state.get_account_by_id(sender_id), true, sender_id);

        let sender_nonce = sender.account.nonce;

        let _recipient =
            AccountWithMetadata::new(state.get_account_by_id(recipient_id), false, sender_id);

        let message = public_transaction::Message::try_new(
            Program::modified_transfer_program().id(),
            vec![sender_id, recipient_id],
            vec![sender_nonce],
            balance_to_move,
        )
        .unwrap();

        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sender_key]);
        let tx = PublicTransaction::new(message, witness_set);
        let res = state.transition_from_public_transaction(&tx);
        assert!(matches!(res, Err(NssaError::InvalidProgramBehavior)));

        let sender_post = state.get_account_by_id(sender_id);
        let recipient_post = state.get_account_by_id(recipient_id);

        let expected_sender_post = {
            let mut this = state.get_account_by_id(sender_id);
            this.balance = sender_init_balance;
            this.nonce = 0;
            this
        };

        let expected_recipient_post = {
            let mut this = state.get_account_by_id(sender_id);
            this.balance = recipient_init_balance;
            this.nonce = 0;
            this
        };

        assert_eq!(expected_sender_post, sender_post);
        assert_eq!(expected_recipient_post, recipient_post);
    }

    #[test]
    fn test_private_authorized_uninitialized_account() {
        let mut state = V02State::new_with_genesis_accounts(&[], &[]);

        // Set up keys for the authorized private account
        let private_keys = test_private_account_keys_1();

        // Create an authorized private account with default values (new account being initialized)
        let authorized_account =
            AccountWithMetadata::new(Account::default(), true, &private_keys.npk());

        let program = Program::authenticated_transfer_program();

        // Set up parameters for the new account
        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &private_keys.vpk());
        let epk = EphemeralPublicKey::from_scalar(esk);

        // Balance to initialize the account with (0 for a new account)
        let balance: u128 = 0;

        let nonce = 0xdeadbeef1;

        // Execute and prove the circuit with the authorized account but no commitment proof
        let (output, proof) = execute_and_prove(
            vec![authorized_account],
            Program::serialize_instruction(balance).unwrap(),
            vec![1],
            vec![nonce],
            vec![(private_keys.npk(), shared_secret)],
            vec![private_keys.nsk],
            vec![None],
            &program.into(),
        )
        .unwrap();

        // Create message from circuit output
        let message = Message::try_from_circuit_output(
            vec![],
            vec![],
            vec![(private_keys.npk(), private_keys.vpk(), epk)],
            output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]);

        let tx = PrivacyPreservingTransaction::new(message, witness_set);
        let result = state.transition_from_privacy_preserving_transaction(&tx);
        assert!(result.is_ok());

        let nullifier = Nullifier::for_account_initialization(&private_keys.npk());
        assert!(state.private_state.1.contains(&nullifier));
    }

    #[test]
    fn test_private_account_claimed_then_used_without_init_flag_should_fail() {
        let mut state = V02State::new_with_genesis_accounts(&[], &[]).with_test_programs();

        // Set up keys for the private account
        let private_keys = test_private_account_keys_1();

        // Step 1: Create a new private account with authorization
        let authorized_account =
            AccountWithMetadata::new(Account::default(), true, &private_keys.npk());

        let claimer_program = Program::claimer();

        // Set up parameters for claiming the new account
        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &private_keys.vpk());
        let epk = EphemeralPublicKey::from_scalar(esk);

        let balance: u128 = 0;
        let nonce = 0xdeadbeef1;

        // Step 2: Execute claimer program to claim the account with authentication
        let (output, proof) = execute_and_prove(
            vec![authorized_account.clone()],
            Program::serialize_instruction(balance).unwrap(),
            vec![1],
            vec![nonce],
            vec![(private_keys.npk(), shared_secret)],
            vec![private_keys.nsk],
            vec![None],
            &claimer_program.into(),
        )
        .unwrap();

        let message = Message::try_from_circuit_output(
            vec![],
            vec![],
            vec![(private_keys.npk(), private_keys.vpk(), epk)],
            output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Claim should succeed
        assert!(
            state
                .transition_from_privacy_preserving_transaction(&tx)
                .is_ok()
        );

        // Verify the account is now initialized (nullifier exists)
        let nullifier = Nullifier::for_account_initialization(&private_keys.npk());
        assert!(state.private_state.1.contains(&nullifier));

        // Prepare new state of account
        let account_metadata = {
            let mut acc = authorized_account.clone();
            acc.account.program_owner = Program::claimer().id();
            acc
        };

        let noop_program = Program::noop();
        let esk2 = [4; 32];
        let shared_secret2 = SharedSecretKey::new(&esk2, &private_keys.vpk());

        let nonce2 = 0xdeadbeef2;

        // Step 3: Try to execute noop program with authentication but without initialization
        let res = execute_and_prove(
            vec![account_metadata],
            Program::serialize_instruction(()).unwrap(),
            vec![1],
            vec![nonce2],
            vec![(private_keys.npk(), shared_secret2)],
            vec![private_keys.nsk],
            vec![None],
            &noop_program.into(),
        );

        assert!(matches!(res, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_public_changer_claimer_no_data_change_no_claim_succeeds() {
        let initial_data = [];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_id = AccountId::new([1; 32]);
        let program_id = Program::changer_claimer().id();
        // Don't change data (None) and don't claim (false)
        let instruction: (Option<Vec<u8>>, bool) = (None, false);

        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], instruction)
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        // Should succeed - no changes made, no claim needed
        assert!(result.is_ok());
        // Account should remain default/unclaimed
        assert_eq!(state.get_account_by_id(account_id), Account::default());
    }

    #[test]
    fn test_public_changer_claimer_data_change_no_claim_fails() {
        let initial_data = [];
        let mut state =
            V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let account_id = AccountId::new([1; 32]);
        let program_id = Program::changer_claimer().id();
        // Change data but don't claim (false) - should fail
        let new_data = vec![1, 2, 3, 4, 5];
        let instruction: (Option<Vec<u8>>, bool) = (Some(new_data), false);

        let message =
            public_transaction::Message::try_new(program_id, vec![account_id], vec![], instruction)
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witness_set);

        let result = state.transition_from_public_transaction(&tx);

        // Should fail - cannot modify data without claiming the account
        assert!(matches!(result, Err(NssaError::InvalidProgramBehavior)));
    }

    #[test]
    fn test_private_changer_claimer_no_data_change_no_claim_succeeds() {
        let program = Program::changer_claimer();
        let sender_keys = test_private_account_keys_1();
        let private_account =
            AccountWithMetadata::new(Account::default(), true, &sender_keys.npk());
        // Don't change data (None) and don't claim (false)
        let instruction: (Option<Vec<u8>>, bool) = (None, false);

        let result = execute_and_prove(
            vec![private_account],
            Program::serialize_instruction(instruction).unwrap(),
            vec![1],
            vec![2],
            vec![(
                sender_keys.npk(),
                SharedSecretKey::new(&[3; 32], &sender_keys.vpk()),
            )],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        // Should succeed - no changes made, no claim needed
        assert!(result.is_ok());
    }

    #[test]
    fn test_private_changer_claimer_data_change_no_claim_fails() {
        let program = Program::changer_claimer();
        let sender_keys = test_private_account_keys_1();
        let private_account =
            AccountWithMetadata::new(Account::default(), true, &sender_keys.npk());
        // Change data but don't claim (false) - should fail
        let new_data = vec![1, 2, 3, 4, 5];
        let instruction: (Option<Vec<u8>>, bool) = (Some(new_data), false);

        let result = execute_and_prove(
            vec![private_account],
            Program::serialize_instruction(instruction).unwrap(),
            vec![1],
            vec![2],
            vec![(
                sender_keys.npk(),
                SharedSecretKey::new(&[3; 32], &sender_keys.vpk()),
            )],
            vec![sender_keys.nsk],
            vec![Some((0, vec![]))],
            &program.into(),
        );

        // Should fail - cannot modify data without claiming the account
        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_malicious_authorization_changer_should_fail_in_privacy_preserving_circuit() {
        // Arrange
        let malicious_program = Program::malicious_authorization_changer();
        let auth_transfers = Program::authenticated_transfer_program();
        let sender_keys = test_public_account_keys_1();
        let recipient_keys = test_private_account_keys_1();

        let sender_account = AccountWithMetadata::new(
            Account {
                program_owner: auth_transfers.id(),
                balance: 100,
                ..Default::default()
            },
            false,
            sender_keys.account_id(),
        );
        let recipient_account =
            AccountWithMetadata::new(Account::default(), true, &recipient_keys.npk());

        let recipient_commitment =
            Commitment::new(&recipient_keys.npk(), &recipient_account.account);
        let state = V02State::new_with_genesis_accounts(
            &[(sender_account.account_id, sender_account.account.balance)],
            std::slice::from_ref(&recipient_commitment),
        )
        .with_test_programs();

        let balance_to_transfer = 10u128;
        let instruction = (balance_to_transfer, auth_transfers.id());

        let recipient_esk = [3; 32];
        let recipient = SharedSecretKey::new(&recipient_esk, &recipient_keys.vpk());

        let mut dependencies = HashMap::new();
        dependencies.insert(auth_transfers.id(), auth_transfers);
        let program_with_deps = ProgramWithDependencies::new(malicious_program, dependencies);

        let recipient_new_nonce = 0xdeadbeef1;

        // Act - execute the malicious program - this should fail during proving
        let result = execute_and_prove(
            vec![sender_account, recipient_account],
            Program::serialize_instruction(instruction).unwrap(),
            vec![0, 1],
            vec![recipient_new_nonce],
            vec![(recipient_keys.npk(), recipient)],
            vec![recipient_keys.nsk],
            vec![state.get_proof_for_commitment(&recipient_commitment)],
            &program_with_deps,
        );

        // Assert - should fail because the malicious program tries to manipulate is_authorized
        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    #[test]
    fn test_state_serialization_roundtrip() {
        let account_id_1 = AccountId::new([1; 32]);
        let account_id_2 = AccountId::new([2; 32]);
        let initial_data = [(account_id_1, 100u128), (account_id_2, 151u128)];
        let state = V02State::new_with_genesis_accounts(&initial_data, &[]).with_test_programs();
        let bytes = borsh::to_vec(&state).unwrap();
        let state_from_bytes: V02State = borsh::from_slice(&bytes).unwrap();
        assert_eq!(state, state_from_bytes);
    }
}
