use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    Identifier, InputAccountIdentity, NullifierPublicKey, PrivateWitness, PublicDiff, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, Data, apply_balance_diff},
    encryption::ViewingPublicKey,
    program::{
        AccountDiffOutput, BlockValidityWindow, CallerData, ChainedCall, Claim,
        DEFAULT_PROGRAM_OWNER, MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId, ProgramOutput,
        TimestampValidityWindow, UpdateFromDiffOutput, validate_execution,
    },
};
use risc0_zkvm::{guest::env, serde::to_vec};

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
    /// The canonical, committed signer set. `is_authorized` for a public account's first sighting
    /// is derived from membership in this list (or PDA-authorization via a caller's seeds) —
    /// never trusted as an independently-reported witness — and the list itself is echoed in the
    /// circuit's output so the sequencer can cross-check it against real signatures.
    signer_account_ids: Vec<AccountId>,
    /// Raw, per-call, unaggregated diffs for public accounts. This, not `post_states`, is what
    /// the circuit ultimately outputs for public accounts: `post_states` is only ever used
    /// internally, to give a later call in the same chain a concrete `pre_state` for an account
    /// an earlier call already touched. See `PrivacyPreservingCircuitOutput::public_diffs`.
    public_diffs: Vec<PublicDiff>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        program_outputs: Vec<ProgramOutput>,
        signer_account_ids: &[AccountId],
        update_from_diff_results: Vec<Data>,
    ) -> Self {
        let mut update_from_diff_results: VecDeque<Data> = update_from_diff_results.into();
        // Build position → (npk, identifier) map for private-PDA pre_states, indexed by position
        // in `account_identities`. The vec is documented as 1:1 with the program's pre_state
        // order, so position here matches `pre_state_position` used downstream in
        // `validate_and_sync_states`.
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
            signer_account_ids: signer_account_ids.to_vec(),
            public_diffs: Vec::new(),
        };

        let Some(first_output) = program_outputs.first() else {
            panic!("No program outputs provided");
        };

        let initial_call = ChainedCall {
            program_id,
            instruction_data: first_output.instruction_data.clone(),
            pre_states: first_output.pre_states.clone(),
            pda_seeds: Vec::new(),
        };
        let initial_caller_data = CallerData {
            program_id: None,
            authorized_accounts: HashSet::new(),
        };
        let mut chained_calls =
            VecDeque::<(ChainedCall, CallerData)>::from_iter([(initial_call, initial_caller_data)]);

        let mut program_outputs_iter = program_outputs.into_iter();
        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
            assert!(
                chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
                "Max chained calls depth is exceeded"
            );

            let Some(program_output) = program_outputs_iter.next() else {
                panic!("Insufficient program outputs for chained calls");
            };

            // Check that instruction data in chained call is the instruction data in program output
            assert_eq!(
                chained_call.instruction_data, program_output.instruction_data,
                "Mismatched instruction data between chained call and program output"
            );

            // Check that `program_output` is consistent with the execution of the corresponding
            // program.
            let program_output_words =
                &to_vec(&program_output).expect("program_output must be serializable");
            env::verify(chained_call.program_id, program_output_words).unwrap_or_else(
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

            let authorized_accounts = execution_state.validate_and_sync_states(
                account_identities,
                chained_call.program_id,
                caller_data,
                &chained_call.pda_seeds,
                program_output.pre_states,
                program_output.post_states,
                &mut update_from_diff_results,
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

        assert!(
            update_from_diff_results.is_empty(),
            "Extra update_from_diff_results entries beyond what any diff's diff_data consumed",
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

    /// Validate program pre and post states and populate the execution state.
    ///
    /// Return the set of authorized accounts as the result of the processed
    /// call.
    #[expect(
        clippy::too_many_arguments,
        reason = "each parameter is independently required context (caller identity, PDA scope, \
                  diff-native pre/post states, and the update_from_diff binding queue); bundling \
                  them into a struct wouldn't reduce complexity, only relocate it"
    )]
    fn validate_and_sync_states(
        &mut self,
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        caller: CallerData,
        caller_pda_seeds: &[PdaSeed],
        output_pre_states: Vec<AccountWithMetadata>,
        output_post_states: Vec<AccountDiffOutput>,
        update_from_diff_results: &mut VecDeque<Data>,
    ) -> HashSet<AccountId> {
        let mut authorized_output_accounts = Vec::new();
        for (mut pre, diff_output) in output_pre_states.into_iter().zip(output_post_states) {
            let pre_account_id = pre.account_id;
            let pre_is_authorized = pre.is_authorized;
            // `pre` is fully consumed by the match below (destructured in the `Occupied` arm,
            // moved into `self.pre_states` in the `Vacant` arm), so anything needed afterward —
            // for materializing this account's diff into a full post-state — must be captured
            // now.
            let pre_account = pre.account.clone();
            let post_states_entry = self.post_states.entry(pre.account_id);
            match &post_states_entry {
                Entry::Occupied(occupied) => {
                    #[expect(
                        clippy::shadow_unrelated,
                        reason = "Shadowing is intentional to use all fields"
                    )]
                    let AccountWithMetadata {
                        account: pre_account,
                        account_id: pre_account_id,
                        is_authorized: pre_is_authorized,
                    } = pre;

                    // Ensure that new pre state is the same as known post state
                    assert_eq!(
                        occupied.get(),
                        &pre_account,
                        "Inconsistent pre state for account {pre_account_id}",
                    );

                    let pre_state_position = self
                        .pre_states
                        .iter()
                        .position(|acc| acc.account_id == pre_account_id)
                        .unwrap_or_else(|| {
                            panic!(
                                "Pre state must exist in execution state for account {pre_account_id}",
                            )
                        });

                    assert_authorization_and_record_bindings(
                        &mut self.pda_family_binding,
                        &mut self.private_pda_bound_positions,
                        &self.private_pda_by_position,
                        &self.globally_authorized,
                        &caller,
                        caller_pda_seeds,
                        pre_account_id,
                        pre_state_position,
                        pre_is_authorized,
                    );
                }
                Entry::Vacant(_) => {
                    // Pre state for the initial call
                    let pre_state_position = self.pre_states.len();
                    let external_seed = match account_identities.get(pre_state_position) {
                        Some(InputAccountIdentity::Private(PrivateWitness {
                            vpk,
                            identifier,
                            kind:
                                WitnessKind::Pda {
                                    binding: Some((authority_program_id, seed)),
                                },
                            nullifier,
                            ..
                        })) => {
                            let expected = AccountId::for_private_pda(
                                authority_program_id,
                                seed,
                                &nullifier.npk(),
                                vpk,
                                *identifier,
                            );
                            assert_eq!(
                                pre_account_id, expected,
                                "External seed mismatch for private PDA at position {pre_state_position}"
                            );
                            Some((*authority_program_id, *seed))
                        }
                        _ => None,
                    };
                    // External seed is only consulted the first time the account is seen.
                    // Subsequent calls need no re-check because the entry is already recorded on
                    // private_pda_bound_positions.
                    if let Some((authority_program_id, seed)) = external_seed {
                        bind_private_pda_position(
                            &mut self.private_pda_bound_positions,
                            pre_state_position,
                            authority_program_id,
                            seed,
                        );
                        assert_family_binding(
                            &mut self.pda_family_binding,
                            authority_program_id,
                            seed,
                            pre_account_id,
                        );
                    }
                    let has_private_pda_witness = self
                        .private_pda_by_position
                        .contains_key(&pre_state_position);
                    if has_private_pda_witness {
                        assert_authorization_and_record_bindings(
                            &mut self.pda_family_binding,
                            &mut self.private_pda_bound_positions,
                            &self.private_pda_by_position,
                            &self.globally_authorized,
                            &caller,
                            caller_pda_seeds,
                            pre_account_id,
                            pre_state_position,
                            pre_is_authorized,
                        );
                    }
                    // First sighting of a non-PDA-init account (`!has_private_pda_witness`):
                    // this still runs unconditionally for its caller-PDA-seed-matching side
                    // effects (a private PDA without an external seed legitimately authorizes
                    // via the caller's `pda_seeds`), but the signer-list-derived result is only
                    // *enforced* against `pre.is_authorized` for public accounts, inside
                    // `authorize_first_sight_without_pda_witness`: `is_authorized` has no
                    // downstream security consequence for private accounts (claim semantics are
                    // entirely bypassed for them), and a private `AccountId` can never
                    // legitimately appear in `signer_account_ids` (it's derived from `npk`/`vpk`,
                    // not a real-world signature).
                    //
                    // Replaces the guarantee live-state reconstruction used to provide: once the
                    // sequencer stops reconstructing pre-states from live state (PR3), this is
                    // the circuit's only independent check that `is_authorized` for a top-level
                    // public account was derived honestly rather than self-reported.
                    let is_public = account_identities
                        .get(pre_state_position)
                        .is_some_and(InputAccountIdentity::is_public);
                    if !has_private_pda_witness
                        && authorize_first_sight_without_pda_witness(
                            &mut self.pda_family_binding,
                            &mut self.globally_authorized,
                            &caller,
                            caller_pda_seeds,
                            pre_account_id,
                            pre_is_authorized,
                            is_public,
                            self.signer_account_ids.contains(&pre_account_id),
                        )
                    {
                        // authorize_first_sight_without_pda_witness is only true for PDAs
                        // which will be recorded in output journal.
                        //
                        // Since we are in a privacy circuit, the verifier cannot
                        // replay the transaction to see which public PDAs were
                        // actually authorized. We mark them false as the
                        // verifier checks regular account signatures as well.
                        pre.is_authorized = false;
                    }
                    self.pre_states.push(pre);
                }
            }

            // If an account it authorized, push it to the autorized set.
            if pre_is_authorized {
                authorized_output_accounts.push(pre_account_id);
            }

            let pre_state_position = self
                .pre_states
                .iter()
                .position(|acc| acc.account_id == pre_account_id)
                .expect("Pre state must exist at this point");
            let account_identity = &account_identities[pre_state_position];

            let diff = diff_output.diff();

            let balance = apply_balance_diff(pre_account.balance, diff.diff_balance)
                .expect("balance diff must be valid; validate_execution already checked it");

            // Materialize `diff_data` into the account's new `data`, via a recursive proof: the
            // host already proved this program's own `update_from_diff` on `(pre_account,
            // diff_data)` and added the receipt as an assumption (see `execute_and_prove`); here
            // we reconstruct the exact journal that receipt must have committed and check it via
            // `env::verify`. `update_from_diff_results` supplies the one untrusted piece of that
            // journal we can't derive locally — the resulting `data` — in the same order the host
            // proved these receipts, matching this function's own traversal.
            let data = if let Some(diff_data) = diff.diff_data.clone() {
                // The diff's materialization logic belongs to the account's *owner* program, not
                // necessarily the calling program — falling back to the caller only when the
                // account is still unclaimed (default owner). Must match the host's own
                // resolution in `circuit::execute_and_prove`, since that's the program whose ELF
                // actually produced the receipt being checked below.
                let owner_id: ProgramId = if pre_account.program_owner == DEFAULT_PROGRAM_OWNER {
                    program_id
                } else {
                    pre_account.program_owner.into()
                };
                let data = update_from_diff_results
                    .pop_front()
                    .expect("one update_from_diff_results entry per diff with diff_data");
                let expected_output = UpdateFromDiffOutput {
                    pre_state: pre_account.clone(),
                    diff_data,
                    data: data.clone(),
                };
                let journal_words =
                    to_vec(&expected_output).expect("UpdateFromDiffOutput must be serializable");
                env::verify(owner_id, &journal_words).unwrap_or_else(|_: Infallible| {
                    unreachable!("Infallible error is never constructed")
                });
                data
            } else {
                pre_account.data.clone()
            };

            // Ownership is either inherited unchanged, or explicitly overwritten by a claim —
            // never reverts to default. `AccountDiff` carries no ownership info at all, so this
            // is the only place a materialized account's owner can change.
            let post_program_owner = if let Some(claim) = diff_output.required_claim() {
                // The invoked program can only claim accounts with default program id.
                assert_eq!(
                    pre_account.program_owner, DEFAULT_PROGRAM_OWNER,
                    "Cannot claim an initialized account {pre_account_id}"
                );

                if account_identity.is_public() {
                    match claim {
                        Claim::Authorized => {
                            // Note: no need to check authorized pdas because we have already
                            // checked consistency of authorization above.
                            assert!(
                                pre_is_authorized,
                                "Cannot claim unauthorized account {pre_account_id}"
                            );
                        }
                        Claim::Pda(seed) => {
                            let pda = AccountId::for_public_pda(&program_id, &seed);
                            assert_eq!(
                                pre_account_id, pda,
                                "Invalid PDA claim for account {pre_account_id} which does not match derived PDA {pda}"
                            );
                            assert_family_binding(
                                &mut self.pda_family_binding,
                                program_id,
                                seed,
                                pre_account_id,
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
                                pre_account_id, pda,
                                "Invalid private PDA claim for account {pre_account_id}"
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
                                pre_account_id,
                            );
                        }
                    }
                }

                AccountId::from(program_id)
            } else {
                pre_account.program_owner
            };

            if account_identity.is_public() {
                self.public_diffs.push(PublicDiff {
                    account_id: pre_account_id,
                    executing_program_id: program_id,
                    diff: diff_output,
                });
            }

            post_states_entry.insert_entry(Account {
                program_owner: post_program_owner,
                balance,
                data,
                nonce: pre_account.nonce,
            });
        }

        let mut authorized_accounts = caller.authorized_accounts;
        authorized_accounts.extend(authorized_output_accounts);
        authorized_accounts
    }

    /// Consume self and yield the validity windows, the per-position PDA seed/program map
    /// (recorded during `derive_from_outputs`), the committed signer set, the raw per-call
    /// public diffs, and an iterator over pre and (internally materialized) post states of every
    /// account involved in the execution. The materialized post state is only authoritative for
    /// private accounts — for public ones it was only ever needed internally, for
    /// chain-threading; `public_diffs` is the real output for those. Returning everything
    /// together keeps the fields module-private rather than forcing them visible to downstream
    /// consumers.
    #[expect(
        clippy::type_complexity,
        reason = "tuple bundles several exit values from one consuming call so all fields stay private; a struct would only rename it"
    )]
    pub fn into_parts(
        mut self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        HashMap<usize, (ProgramId, PdaSeed)>,
        Vec<AccountId>,
        Vec<PublicDiff>,
        impl ExactSizeIterator<Item = (AccountWithMetadata, Account)>,
    ) {
        let block_validity_window = self.block_validity_window;
        let timestamp_validity_window = self.timestamp_validity_window;
        let pda_seed_by_position = std::mem::take(&mut self.private_pda_bound_positions);
        let signer_account_ids = std::mem::take(&mut self.signer_account_ids);
        let public_diffs = std::mem::take(&mut self.public_diffs);
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
            signer_account_ids,
            public_diffs,
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

/// Judge a non-private-PDA `pre_state` at its first sighting and resolve its journal mask.
///
/// Either the account is a public PDA in which case the public mask should be changed, or
/// it is a regular account. For PDAs, we assert the family bindings. For regular accounts,
/// add to global authorization set.
fn authorize_first_sight_without_pda_witness(
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    globally_authorized: &mut HashSet<AccountId>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    pre_account_id: AccountId,
    pre_is_authorized: bool,
    is_public: bool,
    is_signer: bool,
) -> bool {
    if let Some((seed, caller_program_id)) =
        match_caller_seed_as_public_pda(caller, caller_pda_seeds, pre_account_id)
    {
        assert!(
            pre_is_authorized,
            "Caller-seeded public PDA must be declared authorized at first sight: {pre_account_id}"
        );
        assert_family_binding(pda_family_binding, caller_program_id, seed, pre_account_id);
        true
    } else {
        // Replaces the guarantee live-state reconstruction used to provide: once the sequencer
        // stops reconstructing pre-states from live state, this is the circuit's only
        // independent check that `is_authorized` for a top-level public account was derived
        // honestly rather than self-reported. `is_authorized` has no downstream security
        // consequence for private accounts (claim semantics are entirely bypassed for them),
        // and a private `AccountId` can never legitimately appear in `signer_account_ids` (it's
        // derived from `npk`/`vpk`, not a real-world signature), so the check is public-only.
        assert!(
            !is_public || pre_is_authorized == is_signer,
            "is_authorized for account {pre_account_id} doesn't match the canonical signer/PDA-authorization sources",
        );
        // If an authorized account is a non-PDA one, it is globally authorized.
        if pre_is_authorized {
            globally_authorized.insert(pre_account_id);
        }
        false
    }
}

/// When a caller seed matches, also records the `(caller, seed) → account_id` family binding
/// and, for the private form, marks the position in `private_pda_bound_positions`. Free
/// function so callers can pass individual `&mut self.*` field borrows without holding a borrow
/// on the surrounding struct's other fields.
#[expect(
    clippy::too_many_arguments,
    reason = "breaking out a context struct does not buy us anything here"
)]
fn assert_authorization_and_record_bindings(
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    private_pda_bound_positions: &mut HashMap<usize, (ProgramId, PdaSeed)>,
    private_pda_by_position: &HashMap<usize, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    globally_authorized: &HashSet<AccountId>,
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    pre_account_id: AccountId,
    pre_state_position: usize,
    pre_is_authorized: bool,
) {
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

    let is_authorized = matched_caller_seed.is_some()
        || globally_authorized.contains(&pre_account_id)
        || caller.authorized_accounts.contains(&pre_account_id);

    assert_eq!(
        pre_is_authorized, is_authorized,
        "Inconsistent authorization for account {pre_account_id}",
    );
}
