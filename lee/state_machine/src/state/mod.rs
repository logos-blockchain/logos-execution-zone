use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, MembershipProof, Nullifier,
    Timestamp,
    account::{Account, AccountId, Data},
    program::{
        PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramId, ProgramSegment, TransactionEvent,
        get_program_via,
    },
};

use crate::{
    error::LeeError,
    merkle_tree::MerkleTree,
    privacy_preserving_transaction::PrivacyPreservingTransaction,
    program::Program,
    public_transaction::PublicTransaction,
    validated_state_diff::{StateDiff, ValidatedStateDiff},
};

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug))]
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
        for commitment in commitments.iter().copied() {
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

#[cfg_attr(test, derive(Debug))]
#[derive(Clone, PartialEq, Eq)]
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

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct V03State {
    public_state: HashMap<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
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
        }
    }
}

impl V03State {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn commitment_root(&self) -> CommitmentSetDigest {
        self.private_state.0.digest()
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
            self.insert_program(&program);
        }
        self
    }

    /// Seeds a builtin as a loader-owned header pointing at one segment holding its `user_elf`.
    /// The header lives at the bijection address (`AccountId::from(program.id())`).
    pub(crate) fn insert_program(&mut self, program: &Program) {
        let header_account_id = AccountId::from(program.id());
        let segment_account_id = genesis_segment_account_id(header_account_id);

        let user_elf = risc0_binfmt::ProgramBinary::decode(program.elf())
            .expect("builtin program must be a valid ProgramBinary")
            .user_elf
            .to_vec();
        let segment = Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::try_from(
                ProgramSegment {
                    bytecode: user_elf,
                    next_segment: None,
                }
                .to_bytes(),
            )
            .expect("elf must fit under DATA_MAX_LENGTH"),
            ..Account::default()
        };
        let header = Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::try_from(
                ProgramHeader {
                    image_id: program.id(),
                    program_first_segment: segment_account_id,
                    immutable: true,
                }
                .to_bytes(),
            )
            .expect("program header fits under DATA_MAX_LENGTH"),
            ..Account::default()
        };
        self.public_state.insert(segment_account_id, segment);
        self.public_state.insert(header_account_id, header);
    }

    #[must_use]
    pub fn apply_state_diff(&mut self, diff: ValidatedStateDiff) -> Vec<TransactionEvent> {
        let StateDiff {
            signer_account_ids,
            public_diff,
            new_commitments,
            new_nullifiers,
            events,
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
        events
    }

    pub fn transition_from_public_transaction(
        &mut self,
        tx: &PublicTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let diff = ValidatedStateDiff::from_public_transaction(tx, self, block_id, timestamp)?;
        Ok(self.apply_state_diff(diff))
    }

    pub fn transition_from_privacy_preserving_transaction(
        &mut self,
        tx: &PrivacyPreservingTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<(), LeeError> {
        let diff =
            ValidatedStateDiff::from_privacy_preserving_transaction(tx, self, block_id, timestamp)?;
        drop(self.apply_state_diff(diff));
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

    /// Borrowing counterpart of [`Self::get_account_by_id`].
    #[must_use]
    pub fn get_account_by_id_ref(&self, account_id: AccountId) -> Option<&Account> {
        self.public_state.get(&account_id)
    }

    /// Looks up a program deployed at its bijection address (`AccountId::from(program_id)`),
    /// reconstructing its bytecode from its header and segment chain.
    ///
    /// Only meaningful for programs deployed at their bijection address — genesis-seeded
    /// builtins, or anything created through the (removed) `ProgramDeploymentTransaction`.
    /// A program deployed through `program_loader` at an arbitrary address must be resolved
    /// through [`get_program_via`] with the real address instead.
    #[must_use]
    pub fn get_program(&self, program_id: ProgramId) -> Option<(ProgramId, Vec<u8>)> {
        let (image_id, user_elf) = get_program_via(AccountId::from(program_id), |account_id| {
            self.get_account_by_id(account_id)
        })?;
        Some((image_id, crate::program::attach_kernel(&user_elf)))
    }

    /// The real `image_id` of whatever program is deployed at `account_id`, or `None` if there
    /// isn't one — used to anchor a private transaction's [`ProgramImageClaim`]s to real chain
    /// state rather than trusting the prover's own claim.
    ///
    /// [`ProgramImageClaim`]: lee_core::ProgramImageClaim
    #[must_use]
    pub fn get_program_image_id(&self, account_id: AccountId) -> Option<ProgramId> {
        get_program_via(account_id, |id| self.get_account_by_id(id)).map(|(image_id, _)| image_id)
    }

    #[must_use]
    pub fn get_proof_for_commitment(&self, commitment: &Commitment) -> Option<MembershipProof> {
        self.private_state.0.get_proof_for(commitment)
    }

    #[must_use]
    pub fn commitment_set_digest(&self) -> CommitmentSetDigest {
        self.private_state.0.digest()
    }

    /// Order-independent fingerprint of the genesis-relevant state: the public account set
    /// (which includes deployed programs' storage accounts) and the commitment-set digest.
    ///
    /// The sequencer and the indexer build the directly-seeded part of genesis
    /// (base builtins plus any directly-seeded accounts) separately from their own
    /// configs, so a divergence there would otherwise go unnoticed. Both nodes log
    /// this at startup; equal values mean the two genesis states agree. Entries are
    /// sorted by id before hashing, so the value does not depend on `HashMap`
    /// iteration order.
    #[must_use]
    pub fn genesis_fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};

        // Destructure so adding a `V03State` field forces a decision here about
        // whether it belongs in the genesis fingerprint.
        let Self {
            public_state,
            private_state,
        } = self;

        let mut accounts: Vec<(&AccountId, &Account)> = public_state.iter().collect();
        accounts.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
        let account_count = u64::try_from(accounts.len()).expect("account count fits in u64");

        let mut hasher = Sha256::new();
        hasher.update(account_count.to_le_bytes());
        for (id, account) in accounts {
            hasher.update(id.as_ref());
            let bytes = borsh::to_vec(account).expect("Account is BorshSerialize");
            let len = u64::try_from(bytes.len()).expect("account encoding fits in u64");
            hasher.update(len.to_le_bytes());
            hasher.update(&bytes);
        }
        hasher.update(private_state.0.digest());

        let mut out = [0_u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
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

/// The deterministic `AccountId` a genesis-seeded builtin's single segment lives at, derived
/// from the header's own bijection address.
///
/// Only `insert_program` needs this — a live `program_loader` deploy has a real signer and picks
/// its own segment addresses instead, since genesis has no signer to ask.
fn genesis_segment_account_id(header_account_id: AccountId) -> AccountId {
    use sha2::{Digest as _, Sha256};
    const GENESIS_SEGMENT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/GenesisSeg/\x00";

    let mut hasher = Sha256::new();
    hasher.update(GENESIS_SEGMENT_ID_PREFIX);
    hasher.update(header_account_id.as_ref());
    AccountId::new(hasher.finalize().into())
}

#[cfg(test)]
pub mod tests;
