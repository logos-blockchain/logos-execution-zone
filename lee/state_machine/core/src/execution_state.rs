use std::collections::{HashMap, HashSet, VecDeque, hash_map::Entry};

use crate::{
    Identifier, InputAccount, InputAccountIdentity, NullifierPublicKey, PrivateWitness,
    WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, BalanceDiffError},
    encryption::ViewingPublicKey,
    program::{
        AccountDiffOutput, BlockValidityWindow, CallContext, CallerData, ChainedCall, Claim,
        ClaimError, DEFAULT_PROGRAM_OWNER, EntryCall, ExecutionValidationError,
        MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramEffects, ProgramId, ProgramOutput,
        TimestampValidityWindow, match_caller_seed_as_public_pda, validate_execution,
        validate_public_claim,
    },
};

#[derive(Debug, thiserror::Error)]
#[error("Duplicate input account {account_id}")]
pub struct DuplicateInputAccount {
    pub account_id: AccountId,
}

/// Every way the walk can reject a transaction. `Provider` carries whatever the per-call step
/// failed with; every other variant is a rule the walk itself enforces.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionWalkError<E> {
    #[error("{0}")]
    Provider(E),

    #[error("Max chained calls depth is exceeded")]
    MaxChainedCallsDepthExceeded,

    #[error("No input supplied for account {account_id}")]
    MissingInputAccount { account_id: AccountId },

    #[error(
        "Private PDA {account_id} is not the account program {program_id:?} derives from its seed"
    )]
    PrivatePdaMismatch {
        account_id: AccountId,
        program_id: ProgramId,
    },

    #[error("private PDA pre_state must have a witnessed npk")]
    MissingPrivatePdaWitness { account_id: AccountId },

    #[error(
        "Two different accounts resolved under the same (program, seed) in one transaction: existing {existing}, new {account_id}"
    )]
    FamilyBindingConflict {
        existing: AccountId,
        account_id: AccountId,
    },

    #[error("Duplicate binding for {account_id}: conflicting (program_id, seed)")]
    ConflictingPrivatePdaBinding { account_id: AccountId },

    #[error(
        "private PDA {account_id} has no proven (seed, npk) binding via Claim::Pda or caller pda_seeds"
    )]
    UnboundPrivatePda { account_id: AccountId },

    #[error("Account {account_id} was modified but not claimed")]
    UnclaimedModifiedDefault { account_id: AccountId },

    #[error("Post state must exist for pre state {account_id}")]
    MissingPostState { account_id: AccountId },

    #[error("There should be non empty intersection in the program output block validity windows")]
    EmptyBlockWindowIntersection,

    #[error(
        "There should be non empty intersection in the program output timestamp validity windows"
    )]
    EmptyTimestampWindowIntersection,

    #[error("Invalid program behavior in program {program_id:?}: {source}")]
    ExecutionValidation {
        program_id: ProgramId,
        // Boxed to keep the error type small
        source: Box<ExecutionValidationError>,
    },

    #[error("Cannot claim an initialized account {account_id}")]
    ClaimedInitializedAccount { account_id: AccountId },

    #[error("{source} in program {program_id:?}")]
    Claim {
        program_id: ProgramId,
        source: ClaimError,
    },

    #[error(
        "balance diff must apply; this is the per-account sufficiency check that rejects the proof: {source}"
    )]
    BalanceDiff {
        account_id: AccountId,
        source: BalanceDiffError,
    },
}

/// What the prover supplied for one private-PDA account, alongside the verdict the walk reaches
/// about it.
struct PrivatePda {
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    /// The owner program and seed, once some path has PROVEN
    /// `AccountId::for_private_pda(program_id, seed, npk, vpk, identifier) == account_id`.
    /// Two paths reach it: a `Claim::Pda(seed)` in a program's `post_state` on that `pre_state`,
    /// or a caller's `ChainedCall.pda_seeds` entry matching under the private derivation. Being
    /// bound is a property, not an event — the same account can legitimately be bound through
    /// both paths in one transaction (a program claims a private PDA and then delegates it), so
    /// re-binding the same pair is accepted and only a DIFFERENT pair is a conflict.
    /// `compute_circuit_output` reads it back to construct `PrivateAccountKind::Pda`.
    binding: Option<(ProgramId, PdaSeed)>,
}

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    pre_states: Vec<AccountWithMetadata>,
    post_states: HashMap<AccountId, Account>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Every private-PDA account the prover supplied, keyed by the id it names. The entry is
    /// built once in `derive` from `npk_vpk_if_private_pda`, so the npk is derived from its
    /// `nsk` only once, and it carries the obligation the walk has to discharge: an entry whose
    /// `binding` is still `None` when the walk ends has no proven link between the supplied npk
    /// and the `account_id`, and the circuit rejects.
    private_pdas: HashMap<AccountId, PrivatePda>,
    /// Across the whole transaction, each `(program_id, seed)` pair may resolve to at most one
    /// `AccountId`. A seed under a program can derive a family of accounts, one public PDA and
    /// one private PDA per distinct npk. Without this check, a single `pda_seeds: [S]` entry in
    /// a chained call could authorize multiple family members at once (different npks under the
    /// same seed) and let a callee mix balances across them. Every claim and every
    /// caller-authorization resolution is recorded here, either as a new `(program, seed)` →
    /// `AccountId` entry or as an equality check against the existing one, making the rule: one
    /// `(program, seed)` → one account per tx.
    pda_family_binding: HashMap<(ProgramId, PdaSeed), AccountId>,
    /// The set containing non-PDA accounts authorized at their first sight, anywhere in the
    /// call tree, remaining authorized throughout all calls.
    globally_authorized: HashSet<AccountId>,
}

impl PrivatePda {
    fn bind<E>(
        &mut self,
        program_id: ProgramId,
        seed: PdaSeed,
        account_id: AccountId,
    ) -> Result<(), ExecutionWalkError<E>> {
        if self
            .binding
            .is_some_and(|bound| bound != (program_id, seed))
        {
            return Err(ExecutionWalkError::ConflictingPrivatePdaBinding { account_id });
        }
        self.binding = Some((program_id, seed));
        Ok(())
    }
}

impl ExecutionState {
    /// Walk the chained calls, validate what each program did, and derive the overall execution
    /// state. `provider` runs one call: it is handed the call context and the `pre_states` the walk
    /// derived for it, and answers with the program's full output. Whoever supplies that output
    /// is also whoever must bind it — in the circuit by verifying a receipt over the journal the
    /// walk's own `CallContext` and `pre_states` reconstruct.
    pub fn derive<E>(
        input_accounts: &HashMap<AccountId, InputAccount>,
        top_level_call: EntryCall,
        mut provider: impl FnMut(CallContext, Vec<AccountWithMetadata>) -> Result<ProgramOutput, E>,
    ) -> Result<Self, ExecutionWalkError<E>> {
        let private_pdas = input_accounts
            .values()
            .filter_map(|input| {
                let (npk, vpk, identifier) = input.identity.npk_vpk_if_private_pda()?;
                Some((
                    input.account_id,
                    PrivatePda {
                        npk,
                        vpk,
                        identifier,
                        binding: None,
                    },
                ))
            })
            .collect();

        let mut execution_state = Self {
            pre_states: Vec::new(),
            post_states: HashMap::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            pda_family_binding: HashMap::new(),
            private_pdas,
            globally_authorized: HashSet::new(),
        };

        let initial_caller_data = CallerData {
            program_id: None,
            authorized_accounts: HashSet::new(),
        };
        let mut chained_calls = VecDeque::<(ChainedCall, CallerData)>::from_iter([(
            top_level_call.into_chained_call(),
            initial_caller_data,
        )]);

        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
            if chain_calls_counter > MAX_NUMBER_CHAINED_CALLS {
                return Err(ExecutionWalkError::MaxChainedCallsDepthExceeded);
            }

            // The caller only names accounts; the protocol delivers them. Rebuilding what this
            // call was owed and handing it to the provider leaves the program no say in the
            // matter: in the circuit a receipt binds the journal, so a program run on other
            // accounts, at other values, or under other authorizations than the ones derived
            // here discharges nothing and the proof fails.
            let pre_states =
                execution_state.derive_pre_states(input_accounts, &caller_data, &chained_call)?;
            let ChainedCall {
                program_id,
                instruction_data,
                ..
            } = chained_call;

            let call = CallContext {
                self_program_id: program_id,
                caller_program_id: caller_data.program_id,
                instruction_data,
            };
            let ProgramOutput {
                pre_states,
                effects,
                ..
            } = provider(call, pre_states).map_err(ExecutionWalkError::Provider)?;
            let ProgramEffects {
                post_states,
                chained_calls: next_calls,
                block_validity_window,
                timestamp_validity_window,
            } = effects;

            let Ok(block_window) = BlockValidityWindow::try_intersect(
                [execution_state.block_validity_window, block_validity_window].into_iter(),
            ) else {
                return Err(ExecutionWalkError::EmptyBlockWindowIntersection);
            };
            let Ok(timestamp_window) = TimestampValidityWindow::try_intersect(
                [
                    execution_state.timestamp_validity_window,
                    timestamp_validity_window,
                ]
                .into_iter(),
            ) else {
                return Err(ExecutionWalkError::EmptyTimestampWindowIntersection);
            };
            execution_state.block_validity_window = block_window;
            execution_state.timestamp_validity_window = timestamp_window;

            // Check that the program is well behaved.
            // See the # Programs section for the definition of the `validate_execution` method.
            validate_execution(&pre_states, &post_states, program_id).map_err(|source| {
                ExecutionWalkError::ExecutionValidation {
                    program_id,
                    source: Box::new(source),
                }
            })?;

            let authorized_accounts = execution_state.apply_states(
                input_accounts,
                program_id,
                caller_data.authorized_accounts,
                pre_states,
                post_states,
            )?;

            for next_call in next_calls.into_iter().rev() {
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

        // Every private-PDA pre_state must have had its npk bound to its account_id, either via
        // a `Claim::Pda(seed)` in some program's post_state or via a caller's `pda_seeds`
        // matching the private derivation. An unbound private-PDA pre_state has no
        // cryptographic link between the supplied npk and the account_id, and must be rejected.
        for pre in &execution_state.pre_states {
            if execution_state
                .private_pdas
                .get(&pre.account_id)
                .is_some_and(|private_pda| private_pda.binding.is_none())
            {
                return Err(ExecutionWalkError::UnboundPrivatePda {
                    account_id: pre.account_id,
                });
            }
        }

        // Check that all modified uninitialized accounts were claimed
        for pre in execution_state
            .pre_states
            .iter()
            .filter(|a| a.account.program_owner == DEFAULT_PROGRAM_OWNER)
        {
            let post = execution_state.post_states.get(&pre.account_id).ok_or(
                ExecutionWalkError::MissingPostState {
                    account_id: pre.account_id,
                },
            )?;
            if pre.account != *post && post.program_owner == DEFAULT_PROGRAM_OWNER {
                return Err(ExecutionWalkError::UnclaimedModifiedDefault {
                    account_id: pre.account_id,
                });
            }
        }

        Ok(execution_state)
    }

    /// Rebuild the `pre_states` a call was owed: the accounts its caller named, at the values
    /// the execution so far leaves them at, under the authorization the transaction can actually
    /// establish.
    fn derive_pre_states<E>(
        &mut self,
        input_accounts: &HashMap<AccountId, InputAccount>,
        caller: &CallerData,
        chained_call: &ChainedCall,
    ) -> Result<Vec<AccountWithMetadata>, ExecutionWalkError<E>> {
        let mut pre_states = Vec::with_capacity(chained_call.accounts.len());
        for &account_id in &chained_call.accounts {
            let (account, is_authorized) = match self.post_states.get(&account_id).cloned() {
                Some(account) => {
                    let is_authorized = derive_authorization_and_record_bindings(
                        &mut self.pda_family_binding,
                        &mut self.private_pdas,
                        &self.globally_authorized,
                        caller,
                        &chained_call.pda_seeds,
                        account_id,
                    )?;
                    (account, is_authorized)
                }
                None => self.derive_first_sight(
                    input_accounts,
                    caller,
                    &chained_call.pda_seeds,
                    account_id,
                )?,
            };
            pre_states.push(AccountWithMetadata {
                account,
                is_authorized,
                account_id,
            });
        }
        Ok(pre_states)
    }

    /// Resolve an account the walk has not reached before and record it. Its value, and for a
    /// regular account its credential, come from the input; a PDA's authorization is derived.
    /// Returns what the program was handed, which for a delegated public PDA is not what we
    /// store.
    fn derive_first_sight<E>(
        &mut self,
        input_accounts: &HashMap<AccountId, InputAccount>,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        account_id: AccountId,
    ) -> Result<(Account, bool), ExecutionWalkError<E>> {
        let InputAccount {
            account,
            is_authorized: attested,
            identity,
            ..
        } = input_accounts
            .get(&account_id)
            .ok_or(ExecutionWalkError::MissingInputAccount { account_id })?;

        // External seed is only consulted the first time the account is seen. Subsequent calls
        // need no re-check because the account's binding is already recorded.
        if let InputAccountIdentity::Private(PrivateWitness {
            kind:
                WitnessKind::Pda {
                    binding: Some((authority_program_id, seed)),
                },
            ..
        }) = identity
        {
            self.bind_verified_private_pda(*authority_program_id, *seed, account_id)?;
        }

        let (is_authorized, stored_is_authorized) = if self.private_pdas.contains_key(&account_id) {
            let derived = derive_authorization_and_record_bindings(
                &mut self.pda_family_binding,
                &mut self.private_pdas,
                &self.globally_authorized,
                caller,
                caller_pda_seeds,
                account_id,
            )?;
            (derived, derived)
        } else if let Some((seed, caller_program_id)) =
            match_caller_seed_as_public_pda(caller, caller_pda_seeds, account_id)
        {
            assert_family_binding(
                &mut self.pda_family_binding,
                caller_program_id,
                seed,
                account_id,
            )?;
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
        Ok((account.clone(), is_authorized))
    }

    /// Record `account_id` as the private PDA `program_id` derives from `seed`, having proven
    /// that derivation against the account's own witnessed npk/vpk/identifier.
    fn bind_verified_private_pda<E>(
        &mut self,
        program_id: ProgramId,
        seed: PdaSeed,
        account_id: AccountId,
    ) -> Result<(), ExecutionWalkError<E>> {
        let private_pda = self
            .private_pdas
            .get_mut(&account_id)
            .ok_or(ExecutionWalkError::MissingPrivatePdaWitness { account_id })?;
        let expected = AccountId::for_private_pda(
            &program_id,
            &seed,
            &private_pda.npk,
            &private_pda.vpk,
            private_pda.identifier,
        );
        if account_id != expected {
            return Err(ExecutionWalkError::PrivatePdaMismatch {
                account_id,
                program_id,
            });
        }
        private_pda.bind(program_id, seed, account_id)?;
        assert_family_binding(&mut self.pda_family_binding, program_id, seed, account_id)
    }

    /// Settle a call's claims, carry its accounts forward, and return the set of accounts its own
    /// callees inherit as authorized.
    fn apply_states<E>(
        &mut self,
        input_accounts: &HashMap<AccountId, InputAccount>,
        program_id: ProgramId,
        mut authorized_accounts: HashSet<AccountId>,
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountDiffOutput>,
    ) -> Result<HashSet<AccountId>, ExecutionWalkError<E>> {
        for (pre, diff_output) in pre_states.into_iter().zip(post_states) {
            let account_id = pre.account_id;

            if pre.is_authorized {
                authorized_accounts.insert(account_id);
            }

            if let Some(claim) = diff_output.claim() {
                // The invoked program can only claim accounts with default program id.
                if pre.account.program_owner != DEFAULT_PROGRAM_OWNER {
                    return Err(ExecutionWalkError::ClaimedInitializedAccount { account_id });
                }

                if input_accounts[&account_id].identity.is_public() {
                    // Authorization itself was settled when the pre_states were derived, so the
                    // `Authorized` rule reads the already-derived flag.
                    validate_public_claim(claim, &pre, program_id)
                        .map_err(|source| ExecutionWalkError::Claim { program_id, source })?;
                    if let Claim::Pda(seed) = claim {
                        assert_family_binding(
                            &mut self.pda_family_binding,
                            program_id,
                            seed,
                            account_id,
                        )?;
                    }
                } else {
                    // Private accounts: don't enforce the claim semantics. Unauthorized private
                    // claiming is intentionally allowed
                    match claim {
                        Claim::Authorized => {}
                        Claim::Pda(seed) => {
                            self.bind_verified_private_pda(program_id, seed, account_id)?;
                        }
                    }
                }
            }

            let post = diff_output
                .materialize(&pre.account, program_id)
                .map_err(|source| ExecutionWalkError::BalanceDiff { account_id, source })?;
            self.post_states.insert(account_id, post);
        }

        Ok(authorized_accounts)
    }

    /// Consume self and yield the validity windows, the per-account PDA seed/program map
    /// (recorded during `derive`), and an iterator over pre and post states of each
    /// account involved in the execution, in first-sight order. Returning everything together
    /// keeps the fields module-private rather than forcing them visible to downstream consumers.
    #[expect(
        clippy::type_complexity,
        reason = "tuple bundles four exit values from one consuming call so all fields stay private; a struct would only rename it"
    )]
    #[must_use]
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
        let pda_seed_by_account = std::mem::take(&mut self.private_pdas)
            .into_iter()
            .filter_map(|(account_id, private_pda)| Some((account_id, private_pda.binding?)))
            .collect();
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
pub fn index_by_account_id(
    input_accounts: Vec<InputAccount>,
) -> Result<HashMap<AccountId, InputAccount>, DuplicateInputAccount> {
    let mut indexed = HashMap::with_capacity(input_accounts.len());
    for input in input_accounts {
        let account_id = input.account_id;
        if indexed.insert(account_id, input).is_some() {
            return Err(DuplicateInputAccount { account_id });
        }
    }
    Ok(indexed)
}

/// Record or re-verify the `(program_id, seed) → account_id` family binding for the
/// transaction. Any claim or caller-seed authorization that resolves a `pre_state` under
/// `(program_id, seed)` must agree with every prior resolution of the same pair; otherwise a
/// single `pda_seeds: [seed]` entry could authorize multiple private-PDA family members at
/// once (different npks under the same seed) and let a callee mix balances across them. Free
/// function so callers can pass `&mut self.pda_family_binding` without holding a borrow on
/// the surrounding struct's other fields.
fn assert_family_binding<E>(
    bindings: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    program_id: ProgramId,
    seed: PdaSeed,
    account_id: AccountId,
) -> Result<(), ExecutionWalkError<E>> {
    match bindings.entry((program_id, seed)) {
        Entry::Vacant(e) => {
            e.insert(account_id);
            Ok(())
        }
        Entry::Occupied(e) if *e.get() == account_id => Ok(()),
        Entry::Occupied(e) => Err(ExecutionWalkError::FamilyBindingConflict {
            existing: *e.get(),
            account_id,
        }),
    }
}

/// Match `account_id` against the caller's seeds interpreted as private-PDA derivations, using
/// the (npk, vpk, identifier) supplied for it. `None` when the account carries no private-PDA
/// witness.
fn match_caller_seed_as_private_pda(
    private_pdas: &HashMap<AccountId, PrivatePda>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    account_id: AccountId,
) -> Option<(PdaSeed, ProgramId)> {
    let PrivatePda {
        npk,
        vpk,
        identifier,
        ..
    } = private_pdas.get(&account_id)?;
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
/// form, the account's own proven binding. Free function so callers can pass individual
/// `&mut self.*` field borrows without holding a borrow on the surrounding struct's other fields.
fn derive_authorization_and_record_bindings<E>(
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    private_pdas: &mut HashMap<AccountId, PrivatePda>,
    globally_authorized: &HashSet<AccountId>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    pre_account_id: AccountId,
) -> Result<bool, ExecutionWalkError<E>> {
    let matched_caller_seed: Option<(PdaSeed, bool, ProgramId)> =
        match_caller_seed_as_public_pda(caller, caller_pda_seeds, pre_account_id)
            .map(|(seed, caller_program_id)| (seed, false, caller_program_id))
            .or_else(|| {
                match_caller_seed_as_private_pda(
                    private_pdas,
                    caller,
                    caller_pda_seeds,
                    pre_account_id,
                )
                .map(|(seed, caller_program_id)| (seed, true, caller_program_id))
            });

    if let Some((seed, is_private_form, caller_program_id)) = matched_caller_seed {
        assert_family_binding(pda_family_binding, caller_program_id, seed, pre_account_id)?;
        if is_private_form {
            private_pdas
                .get_mut(&pre_account_id)
                .ok_or(ExecutionWalkError::MissingPrivatePdaWitness {
                    account_id: pre_account_id,
                })?
                .bind(caller_program_id, seed, pre_account_id)?;
        }
    }

    Ok(matched_caller_seed.is_some()
        || globally_authorized.contains(&pre_account_id)
        || caller.authorized_accounts.contains(&pre_account_id))
}
