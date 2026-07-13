use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, MembershipProof, Nullifier,
    Timestamp,
    account::{Account, AccountId},
    program::ProgramId,
};

use crate::{
    error::LeeError,
    merkle_tree::MerkleTree,
    privacy_preserving_transaction::PrivacyPreservingTransaction,
    program::Program,
    program_deployment_transaction::ProgramDeploymentTransaction,
    public_transaction::PublicTransaction,
    validated_state_diff::{StateDiff, ValidatedStateDiff},
};

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CommitmentSet {
    merkle_tree: MerkleTree,
    commitments: HashMap<Commitment, usize>,
    root_history: HashSet<CommitmentSetDigest>,
}

impl CommitmentSet {
    pub(crate) fn digest(&self) -> CommitmentSetDigest {
        self.merkle_tree.root()
    }

    /// Queries the `CommitmentSet` for a membership proof of commitment.
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
    /// If the capacity is not a `power_of_two`, then capacity is taken
    /// to be the next `power_of_two`.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
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
    const fn new() -> Self {
        Self(BTreeSet::new())
    }

    fn extend(&mut self, new_nullifiers: &[Nullifier]) {
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
pub struct V03State {
    public_state: HashMap<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
    programs: HashMap<ProgramId, Program>,
}

impl Default for V03State {
    fn default() -> Self {
        let mut commitment_set = CommitmentSet::with_capacity(32);
        commitment_set.extend(&[DUMMY_COMMITMENT]);
        let nullifier_set = NullifierSet::new();
        let private_state = (commitment_set, nullifier_set);

        Self {
            public_state: HashMap::default(),
            private_state,
            programs: HashMap::default(),
        }
    }
}

impl V03State {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Initializes state with given public account balances leaving other account fields at their
    /// default values.
    #[must_use]
    pub fn with_public_account_balances(
        mut self,
        balances: impl IntoIterator<Item = (AccountId, u128)>,
    ) -> Self {
        let public_accounts = balances.into_iter().map(|(account_id, balance)| {
            (
                account_id,
                Account {
                    balance,
                    ..Account::default()
                },
            )
        });
        self.public_state.extend(public_accounts);
        self
    }

    /// Initializes state with given public accounts.
    #[must_use]
    pub fn with_public_accounts(
        mut self,
        public_accounts: impl IntoIterator<Item = (AccountId, Account)>,
    ) -> Self {
        self.public_state.extend(public_accounts);
        self
    }

    /// Initializes state with given private accounts.
    #[must_use]
    pub fn with_private_accounts(
        mut self,
        private_accounts: impl IntoIterator<Item = (Commitment, Nullifier)>,
    ) -> Self {
        let (commitments, nullifiers): (Vec<Commitment>, Vec<Nullifier>) =
            private_accounts.into_iter().unzip();
        self.private_state.0.extend(&commitments);
        self.private_state.1.extend(&nullifiers);
        self
    }

    /// Initializes state with given builtin programs.
    #[must_use]
    pub fn with_programs(mut self, programs: impl IntoIterator<Item = Program>) -> Self {
        for program in programs {
            self.insert_program(program);
        }
        self
    }

    pub(crate) fn insert_program(&mut self, program: Program) {
        self.programs.insert(program.id(), program);
    }

    /// Seeds a single genesis account that is not produced by any transaction
    /// (e.g. the cross-zone inbox config or a bridge-lock holding). Lets the
    /// sequencer and indexer seed identical zone-specific state after building
    /// the shared initial state.
    pub fn insert_genesis_account(&mut self, account_id: AccountId, account: Account) {
        self.public_state.insert(account_id, account);
    }

    pub fn apply_state_diff(&mut self, diff: ValidatedStateDiff) {
        let StateDiff {
            signer_account_ids,
            public_diff,
            new_commitments,
            new_nullifiers,
            program,
        } = diff.into_state_diff();
        #[expect(
            clippy::iter_over_hash_type,
            reason = "Iteration order doesn't matter here"
        )]
        for (account_id, account) in public_diff {
            *self.get_account_by_id_mut(account_id) = account;
        }
        for account_id in signer_account_ids {
            self.get_account_by_id_mut(account_id)
                .nonce
                .public_account_nonce_increment();
        }
        self.private_state.0.extend(&new_commitments);
        self.private_state.1.extend(&new_nullifiers);
        if let Some(program) = program {
            self.insert_program(program);
        }
    }

    pub fn transition_from_public_transaction(
        &mut self,
        tx: &PublicTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<(), LeeError> {
        let diff = ValidatedStateDiff::from_public_transaction(tx, self, block_id, timestamp)?;
        self.apply_state_diff(diff);
        Ok(())
    }

    pub fn transition_from_privacy_preserving_transaction(
        &mut self,
        tx: &PrivacyPreservingTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<(), LeeError> {
        let diff =
            ValidatedStateDiff::from_privacy_preserving_transaction(tx, self, block_id, timestamp)?;
        self.apply_state_diff(diff);
        Ok(())
    }

    pub fn transition_from_program_deployment_transaction(
        &mut self,
        tx: &ProgramDeploymentTransaction,
    ) -> Result<(), LeeError> {
        let diff = ValidatedStateDiff::from_program_deployment_transaction(tx, self)?;
        self.apply_state_diff(diff);
        Ok(())
    }

    fn get_account_by_id_mut(&mut self, account_id: AccountId) -> &mut Account {
        self.public_state.entry(account_id).or_default()
    }

    #[must_use]
    pub fn get_account_by_id(&self, account_id: AccountId) -> Account {
        self.public_state
            .get(&account_id)
            .cloned()
            .unwrap_or_else(Account::default)
    }

    #[must_use]
    pub fn get_proof_for_commitment(&self, commitment: &Commitment) -> Option<MembershipProof> {
        self.private_state.0.get_proof_for(commitment)
    }

    pub(crate) const fn programs(&self) -> &HashMap<ProgramId, Program> {
        &self.programs
    }

    #[must_use]
    pub fn commitment_set_digest(&self) -> CommitmentSetDigest {
        self.private_state.0.digest()
    }

    pub(crate) fn check_commitments_are_new(
        &self,
        new_commitments: &[Commitment],
    ) -> Result<(), LeeError> {
        for commitment in new_commitments {
            if self.private_state.0.contains(commitment) {
                return Err(LeeError::InvalidInput("Commitment already seen".to_owned()));
            }
        }
        Ok(())
    }

    pub(crate) fn check_nullifiers_are_valid(
        &self,
        new_nullifiers: &[(Nullifier, CommitmentSetDigest)],
    ) -> Result<(), LeeError> {
        for (nullifier, digest) in new_nullifiers {
            if self.private_state.1.contains(nullifier) {
                return Err(LeeError::InvalidInput("Nullifier already seen".to_owned()));
            }
            if !self.private_state.0.root_history.contains(digest) {
                return Err(LeeError::InvalidInput(
                    "Unrecognized commitment set digest".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl V03State {
    pub fn force_insert_account(&mut self, account_id: AccountId, account: Account) {
        self.public_state.insert(account_id, account);
    }
}

#[cfg(test)]
pub mod tests;
