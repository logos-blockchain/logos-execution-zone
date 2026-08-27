use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    Identifier, InputAccount, InputAccountIdentity, NullifierPublicKey, PrivateWitness,
    WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, apply_balance_diff},
    encryption::ViewingPublicKey,
    program::{
        AccountDiffOutput, BlockValidityWindow, CallContext, CallerData, ChainedCall, Claim,
        DEFAULT_PROGRAM_OWNER, MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramEffects, ProgramId,
        ProgramOutput, TimestampValidityWindow, match_caller_seed_as_private_pda,
        match_caller_seed_as_public_pda, validate_execution,
    },
};
use risc0_zkvm::guest::env;

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    pre_states: Vec<AccountWithMetadata>,
    post_states: HashMap<AccountId, Account>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Private-PDA accounts whose supplied npk has been bound to their `AccountId` via a proven
    /// `AccountId::for_private_pda(program_id, seed, npk, vpk, identifier)` check.
    /// Two proof paths populate this set: a `Claim::Pda(seed)` in a program's `post_state` on
    /// that `pre_state`, or a caller's `ChainedCall.pda_seeds` entry matching that `pre_state`
    /// under the private derivation. Binding is an idempotent property, not an event: the same
    /// account can legitimately be bound through both paths in the same tx (e.g. a program
    /// claims a private PDA and then delegates it to a callee), and the map uses `contains_key`,
    /// not `assert!(insert)`. After the main loop, every private-PDA account must appear in this
    /// map; otherwise the npk is unbound and the circuit rejects.
    /// The stored `(ProgramId, PdaSeed)` is the owner program and seed, used in
    /// `compute_circuit_output` to construct `PrivateAccountKind::Pda { program_id, seed,
    /// identifier }`.
    private_pda_bindings: HashMap<AccountId, (ProgramId, PdaSeed)>,
    /// Across the whole transaction, each `(program_id, seed)` pair may resolve to at most one
    /// `AccountId`. A seed under a program can derive a family of accounts, one public PDA and
    /// one private PDA per distinct npk. Without this check, a single `pda_seeds: [S]` entry in
    /// a chained call could authorize multiple family members at once (different npks under the
    /// same seed) and let a callee mix balances across them. Every claim and every
    /// caller-authorization resolution is recorded here, either as a new `(program, seed)` →
    /// `AccountId` entry or as an equality check against the existing one, making the rule: one
    /// `(program, seed)` → one account per tx.
    pda_family_binding: HashMap<(ProgramId, PdaSeed), AccountId>,
    /// The (npk, vpk, identifier) supplied for each private-PDA account. Built once in
    /// `derive` by walking `input_accounts` and consulting `npk_vpk_if_private_pda`,
    /// so the npk is derived from its `nsk` only once. Used later by the claim and caller-seeds
    /// authorization paths to verify `AccountId::for_private_pda(program_id, seed, npk, vpk,
    /// identifier) == pre_state.account_id`.
    private_pda_witnesses: HashMap<AccountId, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    /// The set containing non-PDA accounts authorized at their first sight, anywhere in the
    /// call tree, remaining authorized throughout all calls.
    globally_authorized: HashSet<AccountId>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive(
        input_accounts: &HashMap<AccountId, InputAccount>,
        program_effects: Vec<ProgramEffects>,
        top_level_call: ChainedCall,
    ) -> Self {
        let private_pda_witnesses = input_accounts
            .values()
            .filter_map(|input| Some((input.account_id, input.identity.npk_vpk_if_private_pda()?)))
            .collect();

        let block_validity_window = BlockValidityWindow::try_intersect(
            program_effects
                .iter()
                .map(|effects| effects.block_validity_window),
        )
        .expect(
            "There should be non empty intersection in the program output block validity windows",
        );
        let timestamp_validity_window = TimestampValidityWindow::try_intersect(
            program_effects
                .iter()
                .map(|effects| effects.timestamp_validity_window),
        )
        .expect(
            "There should be non empty intersection in the program output timestamp validity windows",
        );

        let mut execution_state = Self {
            pre_states: Vec::new(),
            post_states: HashMap::new(),
            block_validity_window,
            timestamp_validity_window,
            private_pda_bindings: HashMap::new(),
            pda_family_binding: HashMap::new(),
            private_pda_witnesses,
            globally_authorized: HashSet::new(),
        };

        let initial_caller_data = CallerData {
            program_id: None,
            authorized_accounts: HashSet::new(),
        };
        let mut chained_calls = VecDeque::<(ChainedCall, CallerData)>::from_iter([(
            top_level_call,
            initial_caller_data,
        )]);

        let mut program_effects_iter = program_effects.into_iter();
        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
            assert!(
                chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
                "Max chained calls depth is exceeded"
            );

            let effects = program_effects_iter
                .next()
                .expect("Insufficient program effects for chained calls");

            // The caller only names accounts; the protocol delivers them. Rebuilding what this
            // call was owed and splicing it into the journal leaves the program no say in the
            // matter: a receipt binds the journal, so a program run on other accounts, at other
            // values, or under other authorizations than the ones derived here discharges
            // nothing and the proof fails.
            let pre_states =
                execution_state.derive_pre_states(input_accounts, &caller_data, &chained_call);
            let ChainedCall {
                program_id,
                instruction_data,
                ..
            } = chained_call;

            let program_output = ProgramOutput {
                call: CallContext {
                    self_program_id: program_id,
                    caller_program_id: caller_data.program_id,
                    instruction_data,
                },
                pre_states,
                effects,
            };
            let program_output_frame = lee_core::to_borsh_frame(&program_output);
            env::verify(program_id, &program_output_frame).unwrap_or_else(|_: Infallible| {
                unreachable!("Infallible error is never constructed")
            });

            // Check that the program is well behaved.
            // See the # Programs section for the definition of the `validate_execution` method.
            let validated_execution = validate_execution(
                &program_output.pre_states,
                &program_output.effects.post_states,
                program_id,
            );
            if let Err(err) = validated_execution {
                panic!("Invalid program behavior in program {program_id:?}: {err}");
            }

            let authorized_accounts = execution_state.apply_states(
                input_accounts,
                program_id,
                caller_data.authorized_accounts,
                program_output.pre_states,
                program_output.effects.post_states,
            );

            for next_call in program_output.effects.chained_calls.into_iter().rev() {
                // Push the call with newly-authorized account set.
                chained_calls.push_front((
                    next_call,
                    CallerData {
                        program_id: Some(program_id),
                        authorized_accounts: authorized_accounts.clone(),
                    },
                ));
            }
            chain_calls_counter = chain_calls_counter.checked_add(1).expect(
                "Chain calls counter should not overflow as it checked before incrementing",
            );
        }

        assert!(
            program_effects_iter.next().is_none(),
            "Inner call without a chained call found",
        );

        // Every private-PDA pre_state must have had its npk bound to its account_id, either via
        // a `Claim::Pda(seed)` in some program's post_state or via a caller's `pda_seeds`
        // matching the private derivation. An unbound private-PDA pre_state has no
        // cryptographic link between the supplied npk and the account_id, and must be rejected.
        for pre in &execution_state.pre_states {
            if execution_state
                .private_pda_witnesses
                .contains_key(&pre.account_id)
            {
                assert!(
                    execution_state
                        .private_pda_bindings
                        .contains_key(&pre.account_id),
                    "private PDA {} has no proven (seed, npk) binding via Claim::Pda or caller pda_seeds",
                    pre.account_id
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
    /// establish.
    fn derive_pre_states(
        &mut self,
        input_accounts: &HashMap<AccountId, InputAccount>,
        caller: &CallerData,
        chained_call: &ChainedCall,
    ) -> Vec<AccountWithMetadata> {
        let mut pre_states = Vec::with_capacity(chained_call.accounts.len());
        for &account_id in &chained_call.accounts {
            let (account, is_authorized) = match self.post_states.get(&account_id).cloned() {
                Some(account) => {
                    let is_authorized = derive_authorization_and_record_bindings(
                        &mut self.pda_family_binding,
                        &mut self.private_pda_bindings,
                        &self.private_pda_witnesses,
                        &self.globally_authorized,
                        caller,
                        &chained_call.pda_seeds,
                        account_id,
                    );
                    (account, is_authorized)
                }
                None => self.derive_first_sight(
                    input_accounts,
                    caller,
                    &chained_call.pda_seeds,
                    account_id,
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
        input_accounts: &HashMap<AccountId, InputAccount>,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        account_id: AccountId,
    ) -> (Account, bool) {
        let InputAccount {
            account,
            is_authorized: attested,
            identity,
            ..
        } = input_accounts
            .get(&account_id)
            .unwrap_or_else(|| panic!("No input supplied for account {account_id}"));

        // External seed is only consulted the first time the account is seen. Subsequent calls
        // need no re-check because the entry is already recorded on private_pda_bindings.
        if let InputAccountIdentity::Private(PrivateWitness {
            vpk,
            identifier,
            kind:
                WitnessKind::Pda {
                    binding: Some((authority_program_id, seed)),
                },
            nullifier,
            ..
        }) = identity
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
                "External seed mismatch for private PDA {account_id}"
            );
            bind_private_pda(
                &mut self.private_pda_bindings,
                account_id,
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
            if self.private_pda_witnesses.contains_key(&account_id) {
                let derived = derive_authorization_and_record_bindings(
                    &mut self.pda_family_binding,
                    &mut self.private_pda_bindings,
                    &self.private_pda_witnesses,
                    &self.globally_authorized,
                    caller,
                    caller_pda_seeds,
                    account_id,
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
                if *attested {
                    self.globally_authorized.insert(account_id);
                }
                (*attested, *attested)
            };

        self.pre_states.push(AccountWithMetadata {
            account: account.clone(),
            is_authorized: stored_is_authorized,
            account_id,
        });
        (account.clone(), is_authorized)
    }

    /// Settle a call's claims, carry its accounts forward, and return the set of accounts its own
    /// callees inherit as authorized.
    fn apply_states(
        &mut self,
        input_accounts: &HashMap<AccountId, InputAccount>,
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

                if input_accounts[&account_id].identity.is_public() {
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
                                .private_pda_witnesses
                                .get(&account_id)
                                .expect("private PDA pre_state must have a witnessed npk");
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
                            bind_private_pda(
                                &mut self.private_pda_bindings,
                                account_id,
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

    /// Consume self and yield the validity windows, the per-account PDA seed/program map
    /// (recorded during `derive`), and an iterator over pre and post states of each
    /// account involved in the execution, in first-sight order. Returning everything together
    /// keeps the fields module-private rather than forcing them visible to downstream consumers.
    #[expect(
        clippy::type_complexity,
        reason = "tuple bundles four exit values from one consuming call so all fields stay private; a struct would only rename it"
    )]
    pub fn into_parts(
        mut self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        HashMap<AccountId, (ProgramId, PdaSeed)>,
        impl ExactSizeIterator<Item = (AccountWithMetadata, Account)>,
    ) {
        let block_validity_window = self.block_validity_window;
        let timestamp_validity_window = self.timestamp_validity_window;
        let pda_seed_by_account = std::mem::take(&mut self.private_pda_bindings);
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
            pda_seed_by_account,
            states_iter,
        )
    }
}

/// Index the per-account inputs by the account each one names. Duplicate ids are rejected rather
/// than silently shadowed, so the map is a faithful view of what the prover supplied.
pub fn index_by_account_id(input_accounts: Vec<InputAccount>) -> HashMap<AccountId, InputAccount> {
    let mut indexed = HashMap::with_capacity(input_accounts.len());
    for input in input_accounts {
        let account_id = input.account_id;
        assert!(
            indexed.insert(account_id, input).is_none(),
            "Duplicate input account {account_id}"
        );
    }
    indexed
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

fn bind_private_pda(
    map: &mut HashMap<AccountId, (ProgramId, PdaSeed)>,
    account_id: AccountId,
    program_id: ProgramId,
    seed: PdaSeed,
) {
    match map.entry(account_id) {
        Entry::Occupied(e) => assert_eq!(
            *e.get(),
            (program_id, seed),
            "Duplicate binding for {account_id}: conflicting (program_id, seed)"
        ),
        Entry::Vacant(e) => {
            e.insert((program_id, seed));
        }
    }
}

/// Whether this call is entitled to `account_id` as an authorized account. When a caller seed
/// matches, also records the `(caller, seed) → account_id` family binding and, for the private
/// form, marks the account in `private_pda_bindings`. Free function so callers can pass
/// individual `&mut self.*` field borrows without holding a borrow on the surrounding struct's
/// other fields.
fn derive_authorization_and_record_bindings(
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    private_pda_bindings: &mut HashMap<AccountId, (ProgramId, PdaSeed)>,
    private_pda_witnesses: &HashMap<AccountId, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    globally_authorized: &HashSet<AccountId>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    pre_account_id: AccountId,
) -> bool {
    let matched_caller_seed: Option<(PdaSeed, bool, ProgramId)> =
        match_caller_seed_as_public_pda(caller, caller_pda_seeds, pre_account_id)
            .map(|(seed, caller_program_id)| (seed, false, caller_program_id))
            .or_else(|| {
                match_caller_seed_as_private_pda(
                    private_pda_witnesses,
                    caller,
                    caller_pda_seeds,
                    pre_account_id,
                )
                .map(|(seed, caller_program_id)| (seed, true, caller_program_id))
            });

    if let Some((seed, is_private_form, caller_program_id)) = matched_caller_seed {
        assert_family_binding(pda_family_binding, caller_program_id, seed, pre_account_id);
        if is_private_form {
            bind_private_pda(
                private_pda_bindings,
                pre_account_id,
                caller_program_id,
                seed,
            );
        }
    }

    matched_caller_seed.is_some()
        || globally_authorized.contains(&pre_account_id)
        || caller.authorized_accounts.contains(&pre_account_id)
}
