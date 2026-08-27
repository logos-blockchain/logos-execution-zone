use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    BareProgramOutput, FirstSightAccount, Identifier, InputAccountIdentity, NullifierPublicKey,
    PrivateWitness, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, apply_balance_diff},
    encryption::ViewingPublicKey,
    program::{
        AccountDiffOutput, BlockValidityWindow, CallerData, ChainedCall, Claim,
        DEFAULT_PROGRAM_OWNER, MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId,
        TimestampValidityWindow, validate_execution,
    },
};
use risc0_zkvm::guest::env;

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    pre_states: Vec<AccountWithMetadata>,
    post_states: HashMap<AccountId, Account>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Positions (in `pre_states`) of private-PDA accounts whose supplied npk has been bound to
    /// their `AccountId` via a proven `AccountId::for_private_pda(program_id, seed, npk, vpk,
    /// identifier)` check.
    /// Two proof paths populate this set: a `Claim::Pda(seed)` in a program's `post_state` on
    /// that `pre_state`, or a caller's `ChainedCall.pda_seeds` entry matching that `pre_state`
    /// under the private derivation. Binding is an idempotent property, not an event: the same
    /// position can legitimately be bound through both paths in the same tx (e.g. a program
    /// claims a private PDA and then delegates it to a callee), and the map uses `contains_key`,
    /// not `assert!(insert)`. After the main loop, every private-PDA position must appear in this
    /// map; otherwise the npk is unbound and the circuit rejects.
    /// The stored `(ProgramId, PdaSeed)` is the owner program and seed, used in
    /// `compute_circuit_output` to construct `PrivateAccountKind::Pda { program_id, seed,
    /// identifier }`.
    private_pda_bound_positions: HashMap<usize, (ProgramId, PdaSeed)>,
    /// Across the whole transaction, each `(program_id, seed)` pair may resolve to at most one
    /// `AccountId`. A seed under a program can derive a family of accounts, one public PDA and
    /// one private PDA per distinct npk. Without this check, a single `pda_seeds: [S]` entry in
    /// a chained call could authorize multiple family members at once (different npks under the
    /// same seed) and let a callee mix balances across them. Every claim and every
    /// caller-authorization resolution is recorded here, either as a new `(program, seed)` →
    /// `AccountId` entry or as an equality check against the existing one, making the rule: one
    /// `(program, seed)` → one account per tx.
    pda_family_binding: HashMap<(ProgramId, PdaSeed), AccountId>,
    /// Map from a private-PDA `pre_state`'s position in `account_identities` to the (npk, vpk,
    /// identifier) supplied for that position. Built once in `derive_from_outputs` by walking
    /// `account_identities` and consulting `npk_vpk_if_private_pda`. Used later by the claim and
    /// caller-seeds authorization paths to verify
    /// `AccountId::for_private_pda(program_id, seed, npk, vpk, identifier) ==
    /// pre_state.account_id`.
    private_pda_by_position: HashMap<usize, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    /// The set containing non-PDA accounts authorized at their first sight, anywhere in the
    /// call tree, remaining authorized throughout all calls.
    globally_authorized: HashSet<AccountId>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        program_outputs: Vec<BareProgramOutput>,
        top_level_pre_state_refs: Vec<AccountId>,
        first_sight_accounts: Vec<FirstSightAccount>,
    ) -> Self {
        // Build position → (npk, identifier) map for private-PDA pre_states, indexed by position
        // in `account_identities`. The vec is documented as 1:1 with the program's pre_state
        // order, so position here matches the position assigned downstream in
        // `derive_pre_states`.
        let mut private_pda_by_position: HashMap<
            usize,
            (NullifierPublicKey, ViewingPublicKey, Identifier),
        > = HashMap::new();
        for (pos, account_identity) in account_identities.iter().enumerate() {
            if let Some((npk, vpk, identifier)) = account_identity.npk_vpk_if_private_pda() {
                private_pda_by_position.insert(pos, (npk, vpk, identifier));
            }
        }

        let block_valid_from = program_outputs
            .iter()
            .filter_map(|output| output.block_validity_window.start())
            .max();
        let block_valid_until = program_outputs
            .iter()
            .filter_map(|output| output.block_validity_window.end())
            .min();
        let ts_valid_from = program_outputs
            .iter()
            .filter_map(|output| output.timestamp_validity_window.start())
            .max();
        let ts_valid_until = program_outputs
            .iter()
            .filter_map(|output| output.timestamp_validity_window.end())
            .min();

        let block_validity_window: BlockValidityWindow = (block_valid_from, block_valid_until)
            .try_into()
            .expect(
                "There should be non empty intersection in the program output block validity windows",
            );
        let timestamp_validity_window: TimestampValidityWindow =
            (ts_valid_from, ts_valid_until)
                .try_into()
                .expect(
                    "There should be non empty intersection in the program output timestamp validity windows",
                );

        let mut execution_state = Self {
            pre_states: Vec::new(),
            post_states: HashMap::new(),
            block_validity_window,
            timestamp_validity_window,
            private_pda_bound_positions: HashMap::new(),
            pda_family_binding: HashMap::new(),
            private_pda_by_position,
            globally_authorized: HashSet::new(),
        };

        let Some(first_output) = program_outputs.first() else {
            panic!("No program outputs provided");
        };

        // The bootstrap call has no caller to name its accounts, so the ids come straight from
        // the input; the splice below is what ties them to the program that ran.
        let initial_call = ChainedCall {
            program_id,
            instruction_data: first_output.instruction_data.clone(),
            accounts: top_level_pre_state_refs,
            pda_seeds: Vec::new(),
        };
        let initial_caller_data = CallerData {
            program_id: None,
            authorized_accounts: HashSet::new(),
        };
        let mut chained_calls =
            VecDeque::<(ChainedCall, CallerData)>::from_iter([(initial_call, initial_caller_data)]);

        let mut program_outputs_iter = program_outputs.into_iter();
        let mut first_sight_accounts = first_sight_accounts.into_iter();
        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
            assert!(
                chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
                "Max chained calls depth is exceeded"
            );

            let Some(bare_output) = program_outputs_iter.next() else {
                panic!("Insufficient program outputs for chained calls");
            };

            // Check that instruction data in chained call is the instruction data in program output
            assert_eq!(
                chained_call.instruction_data, bare_output.instruction_data,
                "Mismatched instruction data between chained call and program output"
            );

            // The caller only names accounts; the protocol delivers them. Rebuilding what this
            // call was owed and splicing it into the journal leaves the program no say in the
            // matter: a receipt binds the journal, so a program run on other accounts, at other
            // values, or under other authorizations than the ones derived here discharges
            // nothing and the proof fails.
            let pre_states = execution_state.derive_pre_states(
                account_identities,
                &caller_data,
                &chained_call,
                &mut first_sight_accounts,
            );

            // Check that `program_output` is consistent with the execution of the corresponding
            // program.
            let program_output = bare_output.into_program_output(pre_states);
            let program_output_frame = lee_core::to_borsh_frame(&program_output);
            env::verify(chained_call.program_id, &program_output_frame).unwrap_or_else(
                |_: Infallible| unreachable!("Infallible error is never constructed"),
            );

            // Verify that the program output's self_program_id matches the expected program ID.
            // This ensures the proof commits to which program produced the output.
            assert_eq!(
                program_output.self_program_id, chained_call.program_id,
                "Program output self_program_id does not match chained call program_id"
            );

            // Verify that the program output's caller_program_id matches the actual caller.
            // This prevents a malicious user from privately executing an internal function
            // by spoofing caller_program_id (e.g. passing caller_program_id = self_program_id
            // to bypass access control checks).
            assert_eq!(
                program_output.caller_program_id, caller_data.program_id,
                "Program output caller_program_id does not match actual caller"
            );

            // Check that the program is well behaved.
            // See the # Programs section for the definition of the `validate_execution` method.
            let validated_execution = validate_execution(
                &program_output.pre_states,
                &program_output.post_states,
                chained_call.program_id,
            );
            if let Err(err) = validated_execution {
                panic!(
                    "Invalid program behavior in program {:?}: {err}",
                    chained_call.program_id
                );
            }

            let authorized_accounts = execution_state.apply_states(
                account_identities,
                chained_call.program_id,
                caller_data.authorized_accounts,
                program_output.pre_states,
                program_output.post_states,
            );

            for next_call in program_output.chained_calls.into_iter().rev() {
                // Push the call with newly-authorized account set.
                chained_calls.push_front((
                    next_call,
                    CallerData {
                        program_id: Some(chained_call.program_id),
                        authorized_accounts: authorized_accounts.clone(),
                    },
                ));
            }
            chain_calls_counter = chain_calls_counter.checked_add(1).expect(
                "Chain calls counter should not overflow as it checked before incrementing",
            );
        }

        assert!(
            program_outputs_iter.next().is_none(),
            "Inner call without a chained call found",
        );

        // Every private-PDA pre_state must have had its npk bound to its account_id, either via
        // a `Claim::Pda(seed)` in some program's post_state or via a caller's `pda_seeds`
        // matching the private derivation. An unbound private-PDA pre_state has no
        // cryptographic link between the supplied npk and the account_id, and must be rejected.
        for (pos, account_identity) in account_identities.iter().enumerate() {
            if account_identity.is_private_pda() {
                assert!(
                    execution_state
                        .private_pda_bound_positions
                        .contains_key(&pos),
                    "private PDA pre_state at position {pos} has no proven (seed, npk) binding via Claim::Pda or caller pda_seeds"
                );
            }
        }

        // Check that all modified uninitialized accounts were claimed
        for (account_id, post) in execution_state
            .pre_states
            .iter()
            .filter(|a| a.account.program_owner == DEFAULT_PROGRAM_OWNER)
            .map(|a| {
                let post = execution_state
                    .post_states
                    .get(&a.account_id)
                    .expect("Post state must exist for pre state");
                (a, post)
            })
            .filter(|(pre_default, post)| pre_default.account != **post)
            .map(|(pre, post)| (pre.account_id, post))
        {
            assert_ne!(
                post.program_owner, DEFAULT_PROGRAM_OWNER,
                "Account {account_id} was modified but not claimed"
            );
        }

        execution_state
    }

    /// Rebuild the `pre_states` a call was owed: the accounts its caller named, at the values
    /// the execution so far leaves them at, under the authorization the transaction can actually
    /// establish. Nothing is read back from the program's own account of its inputs; splicing
    /// this into its journal and verifying is what binds the two together.
    fn derive_pre_states(
        &mut self,
        account_identities: &[InputAccountIdentity],
        caller: &CallerData,
        chained_call: &ChainedCall,
        first_sight_accounts: &mut impl Iterator<Item = FirstSightAccount>,
    ) -> Vec<AccountWithMetadata> {
        let mut pre_states = Vec::with_capacity(chained_call.accounts.len());
        for &account_id in &chained_call.accounts {
            let (account, is_authorized) = match self.post_states.get(&account_id).cloned() {
                Some(account) => {
                    let position = self
                        .pre_states
                        .iter()
                        .position(|acc| acc.account_id == account_id)
                        .unwrap_or_else(|| {
                            panic!(
                                "Pre state must exist in execution state for account {account_id}",
                            )
                        });
                    let is_authorized = derive_authorization_and_record_bindings(
                        &mut self.pda_family_binding,
                        &mut self.private_pda_bound_positions,
                        &self.private_pda_by_position,
                        &self.globally_authorized,
                        caller,
                        &chained_call.pda_seeds,
                        account_id,
                        position,
                    );
                    (account, is_authorized)
                }
                None => self.derive_first_sight(
                    account_identities,
                    caller,
                    &chained_call.pda_seeds,
                    account_id,
                    first_sight_accounts
                        .next()
                        .expect("Every account must come with its first-sight state"),
                ),
            };
            pre_states.push(AccountWithMetadata {
                account,
                is_authorized,
                account_id,
            });
        }
        pre_states
    }

    /// Resolve an account the walk has not reached before and record it. Its value, and for a
    /// regular account its credential, come from the input; a PDA's authorization is derived.
    /// Returns what the program was handed, which for a delegated public PDA is not what we
    /// store.
    fn derive_first_sight(
        &mut self,
        account_identities: &[InputAccountIdentity],
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        account_id: AccountId,
        first_sight: FirstSightAccount,
    ) -> (Account, bool) {
        let position = self.pre_states.len();
        let FirstSightAccount {
            account,
            is_authorized: attested,
        } = first_sight;

        // External seed is only consulted the first time the account is seen. Subsequent calls
        // need no re-check because the entry is already recorded on private_pda_bound_positions.
        if let Some(InputAccountIdentity::Private(PrivateWitness {
            vpk,
            identifier,
            kind:
                WitnessKind::Pda {
                    binding: Some((authority_program_id, seed)),
                },
            nullifier,
            ..
        })) = account_identities.get(position)
        {
            let expected = AccountId::for_private_pda(
                authority_program_id,
                seed,
                &nullifier.npk(),
                vpk,
                *identifier,
            );
            assert_eq!(
                account_id, expected,
                "External seed mismatch for private PDA at position {position}"
            );
            bind_private_pda_position(
                &mut self.private_pda_bound_positions,
                position,
                *authority_program_id,
                *seed,
            );
            assert_family_binding(
                &mut self.pda_family_binding,
                *authority_program_id,
                *seed,
                account_id,
            );
        }

        let (is_authorized, stored_is_authorized) =
            if self.private_pda_by_position.contains_key(&position) {
                let derived = derive_authorization_and_record_bindings(
                    &mut self.pda_family_binding,
                    &mut self.private_pda_bound_positions,
                    &self.private_pda_by_position,
                    &self.globally_authorized,
                    caller,
                    caller_pda_seeds,
                    account_id,
                    position,
                );
                (derived, derived)
            } else if let Some((seed, caller_program_id)) =
                match_caller_seed_as_public_pda(caller, caller_pda_seeds, account_id)
            {
                assert_family_binding(
                    &mut self.pda_family_binding,
                    caller_program_id,
                    seed,
                    account_id,
                );
                // The caller's seeds authorize this PDA, so that is how the host hands it to the
                // callee and how its journal must read. What we store is masked: in a privacy
                // circuit the verifier cannot replay the transaction to see which public PDAs a
                // caller delegated, and it checks regular account signatures against the accounts
                // the output marks authorized.
                (true, false)
            } else {
                // Nothing derives a regular account's authorization. The attested bit is the
                // credential, and it stays bound because the journal has to repeat it.
                if attested {
                    self.globally_authorized.insert(account_id);
                }
                (attested, attested)
            };

        self.pre_states.push(AccountWithMetadata {
            account: account.clone(),
            is_authorized: stored_is_authorized,
            account_id,
        });
        (account, is_authorized)
    }

    /// Settle a call's claims, carry its accounts forward, and return the set of accounts its own
    /// callees inherit as authorized.
    fn apply_states(
        &mut self,
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        mut authorized_accounts: HashSet<AccountId>,
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountDiffOutput>,
    ) -> HashSet<AccountId> {
        for (pre, diff_output) in pre_states.into_iter().zip(post_states) {
            let AccountWithMetadata {
                account: pre_account,
                is_authorized,
                account_id,
            } = pre;

            if is_authorized {
                authorized_accounts.insert(account_id);
            }

            let diff = diff_output.diff();
            let balance = apply_balance_diff(pre_account.balance, diff.diff_balance)
                .expect("balance diff must be valid; validate_execution already checked it");
            let data = diff
                .diff_data
                .clone()
                .unwrap_or_else(|| pre_account.data.clone());

            // Owner is inherited unless a claim overrides it (AccountDiff carries no ownership).
            let post_program_owner = if let Some(claim) = diff_output.claim() {
                // The invoked program can only claim accounts with default program id.
                assert_eq!(
                    pre_account.program_owner, DEFAULT_PROGRAM_OWNER,
                    "Cannot claim an initialized account {account_id}"
                );

                let pre_state_position = self
                    .pre_states
                    .iter()
                    .position(|acc| acc.account_id == account_id)
                    .expect("Pre state must exist at this point");

                let account_identity = &account_identities[pre_state_position];
                if account_identity.is_public() {
                    match claim {
                        Claim::Authorized => {
                            // Note: no need to check authorized pdas because authorization was
                            // already settled when the pre states were derived.
                            assert!(
                                is_authorized,
                                "Cannot claim unauthorized account {account_id}"
                            );
                        }
                        Claim::Pda(seed) => {
                            let pda = AccountId::for_public_pda(&program_id, &seed);
                            assert_eq!(
                                account_id, pda,
                                "Invalid PDA claim for account {account_id} which does not match derived PDA {pda}"
                            );
                            assert_family_binding(
                                &mut self.pda_family_binding,
                                program_id,
                                seed,
                                account_id,
                            );
                        }
                    }
                } else {
                    // Private accounts: don't enforce the claim semantics. Unauthorized private
                    // claiming is intentionally allowed
                    match claim {
                        Claim::Authorized => {}
                        Claim::Pda(seed) => {
                            let (npk, vpk, identifier) = self
                                .private_pda_by_position
                                .get(&pre_state_position)
                                .expect(
                                    "private PDA pre_state must have an npk in the position map",
                                );
                            let pda = AccountId::for_private_pda(
                                &program_id,
                                &seed,
                                npk,
                                vpk,
                                *identifier,
                            );
                            assert_eq!(
                                account_id, pda,
                                "Invalid private PDA claim for account {account_id}"
                            );
                            bind_private_pda_position(
                                &mut self.private_pda_bound_positions,
                                pre_state_position,
                                program_id,
                                seed,
                            );
                            assert_family_binding(
                                &mut self.pda_family_binding,
                                program_id,
                                seed,
                                account_id,
                            );
                        }
                    }
                }

                AccountId::from(program_id)
            } else {
                pre_account.program_owner
            };

            self.post_states.insert(
                account_id,
                Account {
                    program_owner: post_program_owner,
                    balance,
                    data,
                    nonce: pre_account.nonce,
                },
            );
        }

        authorized_accounts
    }

    /// Consume self and yield the validity windows, the per-position PDA seed/program map
    /// (recorded during `derive_from_outputs`), and an iterator over pre and post states of each
    /// account involved in the execution. Returning everything together keeps the
    /// fields module-private rather than forcing them visible to downstream consumers.
    #[expect(
        clippy::type_complexity,
        reason = "tuple bundles four exit values from one consuming call so all fields stay private; a struct would only rename it"
    )]
    pub fn into_parts(
        mut self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        HashMap<usize, (ProgramId, PdaSeed)>,
        impl ExactSizeIterator<Item = (AccountWithMetadata, Account)>,
    ) {
        let block_validity_window = self.block_validity_window;
        let timestamp_validity_window = self.timestamp_validity_window;
        let pda_seed_by_position = std::mem::take(&mut self.private_pda_bound_positions);
        let states_iter = self.pre_states.into_iter().map(move |pre| {
            let post = self
                .post_states
                .remove(&pre.account_id)
                .expect("Account from pre states should exist in state diff");
            (pre, post)
        });
        (
            block_validity_window,
            timestamp_validity_window,
            pda_seed_by_position,
            states_iter,
        )
    }
}

/// Record or re-verify the `(program_id, seed) → account_id` family binding for the
/// transaction. Any claim or caller-seed authorization that resolves a `pre_state` under
/// `(program_id, seed)` must agree with every prior resolution of the same pair; otherwise a
/// single `pda_seeds: [seed]` entry could authorize multiple private-PDA family members at
/// once (different npks under the same seed) and let a callee mix balances across them. Free
/// function so callers can pass `&mut self.pda_family_binding` without holding a borrow on
/// the surrounding struct's other fields.
fn assert_family_binding(
    bindings: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    program_id: ProgramId,
    seed: PdaSeed,
    account_id: AccountId,
) {
    match bindings.entry((program_id, seed)) {
        Entry::Vacant(e) => {
            e.insert(account_id);
        }
        Entry::Occupied(e) => {
            assert_eq!(
                *e.get(),
                account_id,
                "Two different accounts resolved under the same (program, seed) in one transaction: existing {}, new {account_id}",
                e.get()
            );
        }
    }
}

fn bind_private_pda_position(
    map: &mut HashMap<usize, (ProgramId, PdaSeed)>,
    position: usize,
    program_id: ProgramId,
    seed: PdaSeed,
) {
    match map.entry(position) {
        Entry::Occupied(e) => assert_eq!(
            *e.get(),
            (program_id, seed),
            "Duplicate binding at position {position}: conflicting (program_id, seed)"
        ),
        Entry::Vacant(e) => {
            e.insert((program_id, seed));
        }
    }
}

/// Match `account_id` against the caller's seeds under the public-PDA derivation. `None`
/// if no appropriate authorization given.
fn match_caller_seed_as_public_pda(
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    account_id: AccountId,
) -> Option<(PdaSeed, ProgramId)> {
    let caller_program_id = caller.program_id?;
    // Costy for calls with multiple seeds in one call.
    caller_pda_seeds.iter().find_map(|seed| {
        if AccountId::for_public_pda(&caller_program_id, seed) == account_id {
            return Some((*seed, caller_program_id));
        }
        None
    })
}

/// Match `account_id` against the caller's seeds interpreted as private-PDA derivations, using the
/// (npk, vpk, identifier) supplied for this position. `None` when the position carries no
/// private-PDA witness.
fn match_caller_seed_as_private_pda(
    private_pda_by_position: &HashMap<usize, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    account_id: AccountId,
    pre_state_position: usize,
) -> Option<(PdaSeed, ProgramId)> {
    let (npk, vpk, identifier) = private_pda_by_position.get(&pre_state_position)?;
    let caller_program_id = caller.program_id?;
    // Costy for calls with multiple seeds in one call.
    caller_pda_seeds.iter().find_map(|seed| {
        if AccountId::for_private_pda(&caller_program_id, seed, npk, vpk, *identifier) == account_id
        {
            return Some((*seed, caller_program_id));
        }
        None
    })
}

/// Whether this call is entitled to `account_id` as an authorized account. When a caller seed
/// matches, also records the `(caller, seed) → account_id` family binding and, for the private
/// form, marks the position in `private_pda_bound_positions`. Free function so callers can pass
/// individual `&mut self.*` field borrows without holding a borrow on the surrounding struct's
/// other fields.
#[expect(
    clippy::too_many_arguments,
    reason = "breaking out a context struct does not buy us anything here"
)]
fn derive_authorization_and_record_bindings(
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    private_pda_bound_positions: &mut HashMap<usize, (ProgramId, PdaSeed)>,
    private_pda_by_position: &HashMap<usize, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    globally_authorized: &HashSet<AccountId>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    pre_account_id: AccountId,
    pre_state_position: usize,
) -> bool {
    let matched_caller_seed: Option<(PdaSeed, bool, ProgramId)> =
        match_caller_seed_as_public_pda(caller, caller_pda_seeds, pre_account_id)
            .map(|(seed, caller_program_id)| (seed, false, caller_program_id))
            .or_else(|| {
                match_caller_seed_as_private_pda(
                    private_pda_by_position,
                    caller,
                    caller_pda_seeds,
                    pre_account_id,
                    pre_state_position,
                )
                .map(|(seed, caller_program_id)| (seed, true, caller_program_id))
            });

    if let Some((seed, is_private_form, caller_program_id)) = matched_caller_seed {
        assert_family_binding(pda_family_binding, caller_program_id, seed, pre_account_id);
        if is_private_form {
            bind_private_pda_position(
                private_pda_bound_positions,
                pre_state_position,
                caller_program_id,
                seed,
            );
        }
    }

    matched_caller_seed.is_some()
        || globally_authorized.contains(&pre_account_id)
        || caller.authorized_accounts.contains(&pre_account_id)
}
