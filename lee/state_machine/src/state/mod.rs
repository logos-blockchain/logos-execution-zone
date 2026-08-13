use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use fee_core::{FeeError, FeeState, params::MAX_GAS_EXEC};
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
    validated_state_diff::{ExecutionOutcome, StateDiff, ValidatedStateDiff},
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
    programs: HashMap<ProgramId, Program>,
    /// Fee-subsystem state, so base fees, escrow and the payout window persist,
    /// reorg and finalize with the rest of consensus state.
    fee_state: FeeState,
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
            // Also runs the MAX = 2 * TARGET genesis parameter validation.
            fee_state: FeeState::genesis().expect("shipped fee parameters are valid at genesis"),
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
            self.insert_program(program);
        }
        self
    }

    pub(crate) fn insert_program(&mut self, program: Program) {
        self.programs.insert(program.id(), program);
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

    /// Applies `tx` under the protocol-wide cycle ceiling.
    ///
    /// This is the *fee-exempt* execution path: system transactions (clock, bridge-deposit mints,
    /// cross-zone dispatches) and genesis transactions carry no `gas_limit` of their own, so the
    /// block cap is the only bound that applies to them. Charged transactions run under their own
    /// `gas_limit` instead — the block transition drives those through
    /// [`ValidatedStateDiff::from_public_transaction_metered`], since it has to keep the fee of a
    /// reverted transaction while discarding its diff.
    pub fn transition_from_public_transaction(
        &mut self,
        tx: &PublicTransaction,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<ExecutionOutcome, LeeError> {
        let (diff, outcome) = ValidatedStateDiff::from_public_transaction(
            tx,
            self,
            block_id,
            timestamp,
            MAX_GAS_EXEC,
        )?;
        self.apply_state_diff(diff);
        Ok(outcome)
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

    /// Borrowing counterpart of [`Self::get_account_by_id`].
    #[must_use]
    pub fn get_account_by_id_ref(&self, account_id: AccountId) -> Option<&Account> {
        self.public_state.get(&account_id)
    }

    #[must_use]
    pub fn get_proof_for_commitment(&self, commitment: &Commitment) -> Option<MembershipProof> {
        self.private_state.0.get_proof_for(commitment)
    }

    pub(crate) const fn programs(&self) -> &HashMap<ProgramId, Program> {
        &self.programs
    }

    /// Read access to the fee state, for the block transition and for RPC and
    /// indexer consumers.
    #[must_use]
    pub const fn fee_state(&self) -> &FeeState {
        &self.fee_state
    }

    /// Holds `amount` from `account_id`'s balance as a fee reservation.
    ///
    /// SPECS §Block transition step 2: a payer that cannot cover its reservation makes the whole
    /// block invalid, so this is fallible and never partially applied.
    ///
    /// **Moves the balance without asking the owning program**, exactly like [`Self::credit_fee`],
    /// and that is the intent rather than an oversight: fees are a *ledger* effect of the block
    /// transition, not a program invocation. The account's `program_owner` never runs, never sees
    /// the movement, and cannot veto it — a program that maintains an invariant over its accounts'
    /// balances (a vault, an AMM pool) must therefore treat "balance may fall by a fee its payer
    /// authorized" as part of its threat model. The block transition is the only caller.
    ///
    /// # Errors
    ///
    /// [`LeeError::InsufficientFeeBalance`] if the account's balance is below `amount`.
    pub fn debit_fee(&mut self, account_id: AccountId, amount: u128) -> Result<(), LeeError> {
        let account = self.get_account_by_id_mut(account_id);
        let balance = account.balance;
        let Some(remaining) = balance.checked_sub(amount) else {
            return Err(LeeError::InsufficientFeeBalance {
                account_id,
                required: amount,
                available: balance,
            });
        };
        account.balance = remaining;
        Ok(())
    }

    /// Credits `amount` to `account_id`: a released reservation, or the producer's payout and
    /// tips.
    ///
    /// Bypasses the owning program the same way [`Self::debit_fee`] does, and for the same reason.
    /// Note the second-order effect: crediting an account that does not exist yet materializes it
    /// with a non-zero balance and `program_owner` left at the default, which is a shape some
    /// programs refuse to adopt afterwards — see the producer-account note in the task-8 report.
    pub fn credit_fee(&mut self, account_id: AccountId, amount: u128) {
        let account = self.get_account_by_id_mut(account_id);
        account.balance = account
            .balance
            .checked_add(amount)
            .expect("balance overflow: the total supply is below 2^64, so credits fit u128");
    }

    /// Advances the public-account nonces of `account_ids`.
    ///
    /// A successful transaction advances them through its diff. This is the revert path: replay
    /// protection is consumed on inclusion, success or revert, so a charged-but-reverted
    /// transaction may not be re-included (SPECS §Block transition; Q5).
    pub fn advance_replay_nonces(&mut self, account_ids: &[AccountId]) {
        for account_id in account_ids {
            self.get_account_by_id_mut(*account_id)
                .nonce
                .public_account_nonce_increment();
        }
    }

    /// Records the block's settled base revenue and settles this block's producer payout
    /// (SPECS §Revenue distribution). Returns the payout; the caller credits the producer.
    ///
    /// # Errors
    ///
    /// [`FeeError::ConsensusFault`] if the payout would exceed the escrow — unreachable from any
    /// state reachable through this method, and a halt condition rather than a block rejection.
    pub fn distribute_block_revenue(&mut self, revenue_base: u128) -> Result<u128, FeeError> {
        fee_core::distribute(&mut self.fee_state, revenue_base)
    }

    /// Moves both base fees to their values for the next block (SPECS §Base-fee update).
    pub fn update_base_fees(&mut self, gas_used_exec: u64, gas_used_stor: u64) {
        fee_core::step_base_fees(&mut self.fee_state, gas_used_exec, gas_used_stor);
    }

    /// Wholesale mutable access to the fee state.
    ///
    /// Test-only on purpose: consensus state must not be rewritable by an arbitrary crate, so the
    /// block transition goes through the narrow surface above ([`Self::distribute_block_revenue`],
    /// [`Self::update_base_fees`]) instead.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn fee_state_mut(&mut self) -> &mut FeeState {
        &mut self.fee_state
    }

    #[must_use]
    pub fn commitment_set_digest(&self) -> CommitmentSetDigest {
        self.private_state.0.digest()
    }

    /// Order-independent fingerprint of the genesis-relevant state — the public account
    /// set, the deployed program set, the commitment-set digest — plus the compiled-in
    /// fee parameters.
    ///
    /// The sequencer and the indexer build the directly-seeded part of genesis (base
    /// builtins plus any directly-seeded accounts) separately from their own configs, so
    /// a divergence there would otherwise go unnoticed. This is a diagnostic, not a
    /// handshake: nothing compares it across the wire, and its one caller logs it at
    /// sequencer startup for an operator to compare by eye against another node's line.
    ///
    /// Entries are sorted by id before hashing, so the value does not depend on `HashMap`
    /// iteration order.
    #[must_use]
    pub fn genesis_fingerprint(&self) -> [u8; 32] {
        self.genesis_fingerprint_with_params(&fee_core::params::FEE_PARAMS)
    }

    /// [`Self::genesis_fingerprint`] against an arbitrary parameter set, so a test can
    /// vary parameters that are compiled-in constants in production.
    fn genesis_fingerprint_with_params(&self, params: &fee_core::params::FeeParams) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};

        // Destructure so adding a `V03State` field forces a decision here about
        // whether it belongs in the genesis fingerprint.
        // `fee_state` is deliberately excluded: it is fully determined by the
        // compiled-in fee parameters — which are hashed below, in their own right —
        // so it adds nothing to a comparison of the *configured* genesis, and its
        // Borsh encoding is rotation-dependent (ring buffer + cursor), which does
        // not belong in a value nodes compare.
        let Self {
            public_state,
            private_state,
            programs,
            fee_state: _,
        } = self;

        let mut accounts: Vec<(&AccountId, &Account)> = public_state.iter().collect();
        accounts.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));

        let mut program_ids: Vec<ProgramId> = programs.keys().copied().collect();
        program_ids.sort_unstable();

        let account_count = u64::try_from(accounts.len()).expect("account count fits in u64");
        let program_count = u64::try_from(program_ids.len()).expect("program count fits in u64");

        let mut hasher = Sha256::new();
        hasher.update(account_count.to_le_bytes());
        for (id, account) in accounts {
            hasher.update(id.as_ref());
            let bytes = borsh::to_vec(account).expect("Account is BorshSerialize");
            let len = u64::try_from(bytes.len()).expect("account encoding fits in u64");
            hasher.update(len.to_le_bytes());
            hasher.update(&bytes);
        }
        hasher.update(program_count.to_le_bytes());
        for id in program_ids {
            for word in id {
                hasher.update(word.to_le_bytes());
            }
        }
        hasher.update(private_state.0.digest());

        // The fee parameters are compiled-in constants, not state: two nodes built from
        // different revisions agree on every account above and still fork at the first
        // charged block. Folding them in makes that mismatch visible in the logged value.
        // Length-prefixed and in `FeeParams`' documented order.
        let param_words = params.fingerprint_words();
        let param_count = u64::try_from(param_words.len()).expect("parameter count fits in u64");
        hasher.update(param_count.to_le_bytes());
        for word in param_words {
            hasher.update(word.to_le_bytes());
        }

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

#[cfg(test)]
pub mod tests;
