use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    BlockId, Commitment, CommitmentPosition, CommitmentSetDigest, DUMMY_COMMITMENT, EncryptedNote,
    MembershipProof, Nullifier, RecoveryBinding, SealedMessage, Timestamp,
    account::{Account, AccountId, ActorState},
    program::{
        MessageBody, PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramId, Publication,
        TransactionEvent, get_program_via, immutable_mirror_commitment,
    },
};
use rpds::{HashTrieMapSync, HashTrieSetSync, RedBlackTreeMapSync, RedBlackTreeSetSync};

use crate::{
    encoding::persistent::serialize_ordered_map,
    ensure,
    error::LeeError,
    merkle_tree::MerkleTree,
    privacy_preserving_transaction::PrivacyPreservingTransaction,
    program::Program,
    public_transaction::PublicTransaction,
    validated_state_diff::{StateDiff, ValidatedStateDiff},
};

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct CommitmentSet {
    merkle_tree: MerkleTree,
    #[borsh(
        serialize_with = "crate::encoding::persistent::serialize_map",
        deserialize_with = "crate::encoding::persistent::deserialize_map"
    )]
    commitments: HashTrieMapSync<Commitment, usize>,
    #[borsh(
        serialize_with = "crate::encoding::persistent::serialize_set",
        deserialize_with = "crate::encoding::persistent::deserialize_set"
    )]
    root_history: HashTrieSetSync<CommitmentSetDigest>,
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
            .map(|path| {
                (
                    CommitmentPosition::try_from(index).expect("a leaf position fits in u64"),
                    path,
                )
            })
    }

    /// Inserts a list of commitments to the `CommitmentSet`.
    pub(crate) fn extend(&mut self, commitments: &[Commitment]) {
        self.append(commitments, &[]);
    }

    // One transaction's leaves under one recorded root. A message leaf is found by its position
    // alone: one body may be published at several.
    pub(crate) fn append(
        &mut self,
        commitments: &[Commitment],
        messages: &[Commitment],
    ) -> Vec<CommitmentPosition> {
        for commitment in commitments.iter().copied() {
            let index = self.merkle_tree.insert(commitment.to_byte_array());
            self.commitments.insert_mut(commitment, index);
        }
        let positions = messages
            .iter()
            .map(|message| {
                CommitmentPosition::try_from(self.merkle_tree.insert(message.to_byte_array()))
                    .expect("a leaf position fits in u64")
            })
            .collect();
        self.root_history.insert_mut(self.digest());
        positions
    }

    fn get_proof_at(&self, position: CommitmentPosition) -> Option<MembershipProof> {
        let index = usize::try_from(position).ok()?;
        self.merkle_tree
            .get_authentication_path_for(index)
            .map(|path| (position, path))
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
            commitments: HashTrieMapSync::new_sync(),
            root_history: HashTrieSetSync::new_sync(),
        }
    }
}

#[cfg_attr(test, derive(Debug))]
#[derive(Clone, PartialEq, Eq)]
struct NullifierSet(RedBlackTreeSetSync<Nullifier>);

impl NullifierSet {
    fn new() -> Self {
        Self(RedBlackTreeSetSync::new_sync())
    }

    fn extend(&mut self, new_nullifiers: &[Nullifier]) {
        for nullifier in new_nullifiers {
            self.0.insert_mut(*nullifier);
        }
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

        let mut set = RedBlackTreeSetSync::new_sync();
        for n in vec {
            if set.contains(&n) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate nullifier in NullifierSet",
                ));
            }
            set.insert_mut(n);
        }

        Ok(Self(set))
    }
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct V03State {
    #[borsh(
        serialize_with = "crate::encoding::persistent::serialize_map",
        deserialize_with = "crate::encoding::persistent::deserialize_map"
    )]
    public_state: HashTrieMapSync<AccountId, Account>,
    private_state: (CommitmentSet, NullifierSet),
    #[borsh(
        serialize_with = "crate::encoding::persistent::serialize_ordered_map",
        deserialize_with = "crate::encoding::persistent::deserialize_ordered_map"
    )]
    publications: RedBlackTreeMapSync<CommitmentPosition, StoredPublication>,
    #[borsh(
        serialize_with = "crate::encoding::persistent::serialize_ordered_map",
        deserialize_with = "crate::encoding::persistent::deserialize_ordered_map"
    )]
    recovery_bindings: RedBlackTreeMapSync<AccountId, EncryptedNote>,
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Debug))]
enum StoredPublication {
    Clear(MessageBody),
    Sealed(SealedMessage),
}

impl Default for V03State {
    fn default() -> Self {
        let mut commitment_set = CommitmentSet::with_capacity(32);
        commitment_set.extend(&[DUMMY_COMMITMENT]);
        let nullifier_set = NullifierSet::new();
        let private_state = (commitment_set, nullifier_set);

        Self {
            public_state: HashTrieMapSync::new_sync(),
            private_state,
            publications: RedBlackTreeMapSync::new_sync(),
            recovery_bindings: RedBlackTreeMapSync::new_sync(),
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
        for (account_id, balance) in balances {
            self.public_state
                .insert_mut(account_id, Account::funded(balance));
        }
        self
    }

    /// Initializes state with given public accounts.
    #[must_use]
    pub fn with_public_accounts(
        mut self,
        public_accounts: impl IntoIterator<Item = (AccountId, Account)>,
    ) -> Self {
        for (account_id, account) in public_accounts {
            self.public_state.insert_mut(account_id, account);
        }
        self
    }

    /// Initializes state with given private accounts.
    #[cfg(any(test, feature = "test-utils"))]
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

    /// Initializes state with given recovery bindings, under which durable async messages to their
    /// addresses publish.
    #[must_use]
    pub fn with_recovery_bindings(
        mut self,
        bindings: impl IntoIterator<Item = RecoveryBinding>,
    ) -> Self {
        for binding in bindings {
            self.recovery_bindings
                .insert_mut(binding.address, binding.note);
        }
        self
    }

    #[must_use]
    pub fn with_named_programs(
        mut self,
        programs: impl IntoIterator<Item = (AccountId, Program)>,
    ) -> Self {
        for (account_id, program) in programs {
            self.insert_program_at(account_id, &program, true);
        }
        self
    }

    #[must_use]
    pub fn with_programs(self, programs: impl IntoIterator<Item = Program>) -> Self {
        self.with_genesis_programs(programs.into_iter().map(|program| (program, true)))
    }

    #[must_use]
    pub fn with_genesis_programs(
        mut self,
        programs: impl IntoIterator<Item = (Program, bool)>,
    ) -> Self {
        for (program, immutable) in programs {
            self.insert_program(&program, immutable);
        }
        self
    }

    /// Seeds a builtin as a loader-owned header pointing at a segment chain holding its
    /// `user_elf`, chunked the same way a live `program_loader` deploy would.
    pub(crate) fn insert_program(&mut self, program: &Program, immutable: bool) {
        self.insert_program_at(
            AccountId::from_builtin_program(program.id()),
            program,
            immutable,
        );
    }

    fn insert_program_at(
        &mut self,
        header_account_id: AccountId,
        program: &Program,
        immutable: bool,
    ) {
        let binary = risc0_binfmt::ProgramBinary::decode(program.elf())
            .expect("builtin program must be a valid ProgramBinary");
        let image_id: ProgramId =
            risc0_binfmt::compute_image_id(&crate::program::attach_kernel(binary.user_elf))
                .expect("builtin program must have a computable image id")
                .into();
        assert_eq!(
            image_id,
            program.id(),
            "builtin program's image id does not match its bytecode"
        );
        let user_elf = binary.user_elf.to_vec();

        let segment_account_ids: Vec<AccountId> =
            (0..program_loader_core::segment_count(&user_elf))
                .map(|i| genesis_segment_account_id(header_account_id, i))
                .collect();
        let segments = program_loader_core::build_segments(&user_elf, &segment_account_ids)
            .expect("builtin program must split into a valid segment chain");

        for (segment_account_id, segment) in segment_account_ids.iter().zip(segments) {
            let segment = Account::default().with_actor_state(
                PROGRAM_LOADER_ACCOUNT_ID,
                ActorState::from(segment.to_loader_actor_state()),
            );
            self.public_state.insert_mut(*segment_account_id, segment);
        }

        let program_header = ProgramHeader {
            image_id: program.id(),
            program_first_segment: segment_account_ids[0],
            immutable,
        };
        let header = Account::default().with_actor_state(
            PROGRAM_LOADER_ACCOUNT_ID,
            ActorState::from(program_header.to_loader_actor_state()),
        );
        self.public_state.insert_mut(header_account_id, header);

        if immutable {
            let commitment = immutable_mirror_commitment(header_account_id, &program_header);
            self.private_state.0.extend(&[commitment]);
        }
    }

    pub fn apply_state_diff(
        &mut self,
        diff: ValidatedStateDiff,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let StateDiff {
            signer_account_ids,
            public_diff,
            new_commitments,
            new_nullifiers,
            events,
            published,
            recovery_bindings,
        } = diff.into_state_diff();
        // A diff validated against an earlier or another branch's state must still spend each
        // nullifier once, under a root this state knows.
        self.check_nullifiers_are_valid(&new_nullifiers)?;
        let spent: Vec<Nullifier> = new_nullifiers
            .iter()
            .map(|(nullifier, _)| *nullifier)
            .collect();
        ensure!(
            spent.iter().collect::<BTreeSet<_>>().len() == spent.len(),
            LeeError::InvalidInput("Duplicate nullifiers found in state diff".into())
        );
        self.check_recovery_bindings_are_new(&recovery_bindings)?;
        for publication in &published {
            if let Publication::Clear { body, recovery } = publication {
                let address = body.to.account_id;
                ensure!(
                    self.bound_note(&recovery_bindings, address) == Some(recovery),
                    LeeError::InvalidInput(format!(
                        "The recovery binding for {address} differs from the one its publication \
                         carries"
                    ))
                );
            }
        }
        #[expect(
            clippy::iter_over_hash_type,
            reason = "Iteration order doesn't matter here"
        )]
        for (account_id, account) in public_diff {
            self.public_state.insert_mut(account_id, account);
        }
        for account_id in signer_account_ids {
            self.get_account_by_id_mut(account_id)
                .nonce
                .public_account_nonce_increment();
        }
        let messages: Vec<Commitment> = published.iter().map(Publication::commitment).collect();
        let positions = self.private_state.0.append(&new_commitments, &messages);
        self.private_state.1.extend(&spent);
        let stored = published.into_iter().map(|publication| match publication {
            Publication::Clear { body, .. } => StoredPublication::Clear(body),
            Publication::Sealed(sealed) => StoredPublication::Sealed(sealed),
        });
        for (position, publication) in positions.into_iter().zip(stored) {
            self.publications.insert_mut(position, publication);
        }
        for binding in recovery_bindings {
            self.recovery_bindings
                .insert_mut(binding.address, binding.note);
        }
        Ok(events)
    }

    pub fn transition_from_public_transaction(
        &mut self,
        tx: &PublicTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let diff = ValidatedStateDiff::from_public_transaction(tx, self, block_id, timestamp)?;
        self.apply_state_diff(diff)
    }

    pub fn transition_from_privacy_preserving_transaction(
        &mut self,
        tx: &PrivacyPreservingTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<(), LeeError> {
        let diff =
            ValidatedStateDiff::from_privacy_preserving_transaction(tx, self, block_id, timestamp)?;
        self.apply_state_diff(diff)?;
        Ok(())
    }

    fn get_account_by_id_mut(&mut self, account_id: AccountId) -> &mut Account {
        if !self.public_state.contains_key(&account_id) {
            self.public_state.insert_mut(account_id, Account::default());
        }
        self.public_state
            .get_mut(&account_id)
            .expect("the account was just inserted")
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

    #[must_use]
    pub fn recovery_binding(&self, address: AccountId) -> Option<&EncryptedNote> {
        self.recovery_bindings.get(&address)
    }

    pub(crate) fn bound_note<'binding>(
        &'binding self,
        introduced: &'binding [RecoveryBinding],
        address: AccountId,
    ) -> Option<&'binding EncryptedNote> {
        introduced
            .iter()
            .find(|binding| binding.address == address)
            .map(|binding| &binding.note)
            .or_else(|| self.recovery_binding(address))
    }

    pub fn publications_from(
        &self,
        from_position: CommitmentPosition,
    ) -> impl Iterator<Item = (CommitmentPosition, Publication)> {
        self.publications
            .range(from_position..)
            .map(|(position, stored)| {
                let publication = match stored {
                    StoredPublication::Clear(body) => Publication::Clear {
                        body: body.clone(),
                        recovery: self
                            .recovery_binding(body.to.account_id)
                            .expect("a clear publication's address was bound when it was applied")
                            .clone(),
                    },
                    StoredPublication::Sealed(sealed) => Publication::Sealed(sealed.clone()),
                };
                (*position, publication)
            })
    }

    /// Reconstructs a genesis-seeded builtin's bytecode from its header and segment chain at
    /// `account_id` — a program deployed elsewhere via `program_loader` won't be found here.
    #[must_use]
    pub fn get_builtin_program(&self, account_id: AccountId) -> Option<(ProgramId, Vec<u8>)> {
        crate::program::resolve_program(account_id, |id| self.loader_actor_state(id))
    }

    /// The real `image_id` of whatever program is deployed at `account_id`, or `None` if there
    /// isn't one — used to anchor a private transaction's [`ProgramImageClaim`]s to real chain
    /// state rather than trusting the prover's own claim.
    ///
    /// [`ProgramImageClaim`]: lee_core::ProgramImageClaim
    #[must_use]
    pub fn get_program_image_id(&self, account_id: AccountId) -> Option<ProgramId> {
        get_program_via(account_id, |id| self.loader_actor_state(id)).map(|(image_id, _)| image_id)
    }

    pub(crate) fn loader_actor_state(&self, account_id: AccountId) -> Option<&ActorState> {
        self.get_account_by_id_ref(account_id)
            .map(|account| account.data.actor_state(PROGRAM_LOADER_ACCOUNT_ID))
    }

    #[must_use]
    pub fn get_proof_for_commitment(&self, commitment: &Commitment) -> Option<MembershipProof> {
        self.private_state.0.get_proof_for(commitment)
    }

    #[must_use]
    pub fn get_proof_for_position(&self, position: CommitmentPosition) -> Option<MembershipProof> {
        self.private_state.0.get_proof_at(position)
    }

    #[must_use]
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.private_state.1.contains(nullifier)
    }

    #[must_use]
    pub fn commitment_set_digest(&self) -> CommitmentSetDigest {
        self.private_state.0.digest()
    }

    /// Order-independent fingerprint of the genesis-relevant state: the public account set
    /// (which includes deployed programs' storage accounts), the commitment-set digest, the
    /// publications and the recovery bindings.
    ///
    /// The sequencer and the indexer build the directly-seeded part of genesis
    /// (base builtins plus any directly-seeded accounts) separately from their own
    /// configs, so a divergence there would otherwise go unnoticed. Both nodes log
    /// this at startup; equal values mean the two genesis states agree. Entries are
    /// sorted by id before hashing, so the value does not depend on iteration order.
    #[must_use]
    pub fn genesis_fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};

        // Destructure so adding a `V03State` field forces a decision here about
        // whether it belongs in the genesis fingerprint.
        let Self {
            public_state,
            private_state,
            publications,
            recovery_bindings,
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
        let mut encoded = Vec::new();
        serialize_ordered_map(publications, &mut encoded)
            .and_then(|()| serialize_ordered_map(recovery_bindings, &mut encoded))
            .expect("borsh serialization is infallible");
        hasher.update(encoded);

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
            if !self.is_known_commitment_root(digest) {
                return Err(LeeError::InvalidInput(
                    "Unrecognized commitment set digest".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Whether `digest` is a root the commitment tree has actually had at some point.
    pub(crate) fn is_known_commitment_root(&self, digest: &CommitmentSetDigest) -> bool {
        self.private_state.0.root_history.contains(digest)
    }

    pub(crate) fn check_recovery_bindings_are_new(
        &self,
        bindings: &[RecoveryBinding],
    ) -> Result<(), LeeError> {
        let mut addresses = BTreeSet::new();
        for binding in bindings {
            ensure!(
                addresses.insert(binding.address)
                    && !self.recovery_bindings.contains_key(&binding.address),
                LeeError::InvalidInput(format!(
                    "A recovery binding for {} already exists",
                    binding.address
                ))
            );
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl V03State {
    pub fn force_insert_account(&mut self, account_id: AccountId, account: Account) {
        self.public_state.insert_mut(account_id, account);
    }

    #[must_use]
    pub fn with_empty_public_accounts(
        mut self,
        account_ids: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        for account_id in account_ids {
            if !self.public_state.contains_key(&account_id) {
                self.public_state.insert_mut(account_id, Account::default());
            }
        }
        self
    }
}

/// The deterministic `AccountId` a genesis-seeded builtin's `index`-th segment lives at.
/// Only `insert_program` needs this — a live deploy has a real signer to pick addresses instead.
fn genesis_segment_account_id(header_account_id: AccountId, index: usize) -> AccountId {
    use sha2::{Digest as _, Sha256};
    const GENESIS_SEGMENT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/GenesisSeg/\x00";

    let mut hasher = Sha256::new();
    hasher.update(GENESIS_SEGMENT_ID_PREFIX);
    hasher.update(header_account_id.as_ref());
    hasher.update(
        u32::try_from(index)
            .expect("segment count fits in u32")
            .to_le_bytes(),
    );
    AccountId::new(hasher.finalize().into())
}

#[cfg(test)]
pub mod tests;
