use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    Identifier, InputAccountIdentity, NullifierPublicKey,
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        AccountPostState, BlockValidityWindow, ChainedCall, Claim, DEFAULT_PROGRAM_ID,
        MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow,
        validate_execution,
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
    /// their `AccountId` via a proven `AccountId::for_private_pda(program_id, seed, npk,
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
    /// Map from a private-PDA `pre_state`'s position in `account_identities` to the (npk,
    /// identifier) supplied for that position. Built once in `derive_from_outputs` by walking
    /// `account_identities` and consulting `npk_if_private_pda`. Used later by the claim and
    /// caller-seeds authorization paths to verify
    /// `AccountId::for_private_pda(program_id, seed, npk, identifier) == pre_state.account_id`.
    private_pda_npk_by_position: HashMap<usize, (NullifierPublicKey, Identifier)>,
    authorized_accounts: HashSet<AccountId>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        program_outputs: Vec<ProgramOutput>,
    ) -> Self {
        let private_pda_npk_by_position = build_private_pda_npk_map(account_identities);
        let (block_validity_window, timestamp_validity_window) =
            intersect_validity_windows(&program_outputs);

        let mut execution_state = Self {
            pre_states: Vec::new(),
            post_states: HashMap::new(),
            block_validity_window,
            timestamp_validity_window,
            private_pda_bound_positions: HashMap::new(),
            pda_family_binding: HashMap::new(),
            private_pda_npk_by_position,
            authorized_accounts: HashSet::new(),
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
        let mut chained_calls = VecDeque::from_iter([(initial_call, None)]);

        let mut program_outputs_iter = program_outputs.into_iter();
        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_program_id)) = chained_calls.pop_front() {
            assert!(
                chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
                "Max chained calls depth is exceeded"
            );

            let Some(program_output) = program_outputs_iter.next() else {
                panic!("Insufficient program outputs for chained calls");
            };

            verify_program_output(&chained_call, caller_program_id, &program_output);

            for next_call in program_output.chained_calls.iter().rev() {
                chained_calls.push_front((next_call.clone(), Some(chained_call.program_id)));
            }

            execution_state.validate_and_sync_states(
                account_identities,
                chained_call.program_id,
                caller_program_id,
                &chained_call.pda_seeds,
                program_output.pre_states,
                program_output.post_states,
            );
            chain_calls_counter = chain_calls_counter.checked_add(1).expect(
                "Chain calls counter should not overflow as it checked before incrementing",
            );
        }

        assert!(
            program_outputs_iter.next().is_none(),
            "Inner call without a chained call found",
        );

        execution_state.assert_all_pda_positions_bound(account_identities);
        execution_state.assert_modified_accounts_claimed();

        execution_state
    }

    /// Validate program pre and post states and populate the execution state.
    fn validate_and_sync_states(
        &mut self,
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        caller_program_id: Option<ProgramId>,
        caller_pda_seeds: &[PdaSeed],
        output_pre_states: Vec<AccountWithMetadata>,
        output_post_states: Vec<AccountPostState>,
    ) {
        for (pre, mut post) in output_pre_states.into_iter().zip(output_post_states) {
            let pre_account_id = pre.account_id;
            let pre_is_authorized = pre.is_authorized;

            if let Some(existing) = self.post_states.get(&pre.account_id) {
                #[expect(
                    clippy::shadow_unrelated,
                    reason = "Shadowing is intentional to use all fields"
                )]
                let AccountWithMetadata {
                    account: pre_account,
                    account_id: pre_account_id,
                    is_authorized: pre_is_authorized,
                } = pre;

                assert_eq!(
                    existing, &pre_account,
                    "Inconsistent pre state for account {pre_account_id}",
                );

                let (previous_is_authorized, pre_state_position) = self
                    .pre_states
                    .iter()
                    .enumerate()
                    .find(|(_, acc)| acc.account_id == pre_account_id)
                    .map_or_else(
                        || panic!(
                            "Pre state must exist in execution state for account {pre_account_id}",
                        ),
                        |(pos, acc)| (acc.is_authorized, pos),
                    );

                let is_authorized = resolve_authorization_and_record_bindings(
                    &mut self.pda_family_binding,
                    &mut self.private_pda_bound_positions,
                    &self.private_pda_npk_by_position,
                    &mut self.authorized_accounts,
                    pre_account_id,
                    pre_state_position,
                    caller_program_id,
                    caller_pda_seeds,
                    previous_is_authorized,
                );

                assert_eq!(
                    pre_is_authorized, is_authorized,
                    "Inconsistent authorization for account {pre_account_id}",
                );
            } else {
                let pre_state_position = self.pre_states.len();
                resolve_external_seed(
                    account_identities,
                    pre_state_position,
                    pre_account_id,
                    pre.is_authorized,
                    &mut self.private_pda_bound_positions,
                    &mut self.pda_family_binding,
                );
                self.pre_states.push(pre);
            }

            if let Some(claim) = post.required_claim() {
                self.process_claim(
                    account_identities,
                    &mut post,
                    pre_account_id,
                    pre_is_authorized,
                    program_id,
                    claim,
                );
            }

            self.post_states.insert(pre_account_id, post.into_account());
        }
    }

    fn process_claim(
        &mut self,
        account_identities: &[InputAccountIdentity],
        post: &mut AccountPostState,
        pre_account_id: AccountId,
        pre_is_authorized: bool,
        program_id: ProgramId,
        claim: Claim,
    ) {
        assert_eq!(
            post.account().program_owner,
            DEFAULT_PROGRAM_ID,
            "Cannot claim an initialized account {pre_account_id}"
        );

        let pre_state_position = self
            .pre_states
            .iter()
            .position(|acc| acc.account_id == pre_account_id)
            .expect("Pre state must exist at this point");

        let account_identity = &account_identities[pre_state_position];
        if account_identity.is_public() {
            match claim {
                Claim::Authorized => {
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
            match claim {
                Claim::Authorized => {}
                Claim::Pda(seed) => {
                    let (npk, identifier) = self
                        .private_pda_npk_by_position
                        .get(&pre_state_position)
                        .expect("private PDA pre_state must have an npk in the position map");
                    let pda = AccountId::for_private_pda(&program_id, &seed, npk, *identifier);
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

        post.account_mut().program_owner = program_id;
    }

    fn assert_all_pda_positions_bound(&self, account_identities: &[InputAccountIdentity]) {
        for (pos, account_identity) in account_identities.iter().enumerate() {
            if account_identity.is_private_pda() {
                assert!(
                    self.private_pda_bound_positions.contains_key(&pos),
                    "private PDA pre_state at position {pos} has no proven (seed, npk) binding via Claim::Pda or caller pda_seeds"
                );
            }
        }
    }

    fn assert_modified_accounts_claimed(&self) {
        for (account_id, post) in self
            .pre_states
            .iter()
            .filter(|a| a.account.program_owner == DEFAULT_PROGRAM_ID)
            .map(|a| {
                let post = self
                    .post_states
                    .get(&a.account_id)
                    .expect("Post state must exist for pre state");
                (a, post)
            })
            .filter(|(pre_default, post)| pre_default.account != **post)
            .map(|(pre, post)| (pre.account_id, post))
        {
            assert_ne!(
                post.program_owner, DEFAULT_PROGRAM_ID,
                "Account {account_id} was modified but not claimed"
            );
        }
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

fn verify_program_output(
    chained_call: &ChainedCall,
    caller_program_id: Option<ProgramId>,
    program_output: &ProgramOutput,
) {
    assert_eq!(
        chained_call.instruction_data, program_output.instruction_data,
        "Mismatched instruction data between chained call and program output"
    );

    let program_output_words =
        &to_vec(program_output).expect("program_output must be serializable");
    env::verify(chained_call.program_id, program_output_words)
        .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));

    assert_eq!(
        program_output.self_program_id, chained_call.program_id,
        "Program output self_program_id does not match chained call program_id"
    );

    assert_eq!(
        program_output.caller_program_id, caller_program_id,
        "Program output caller_program_id does not match actual caller"
    );

    if let Err(err) = validate_execution(
        &program_output.pre_states,
        &program_output.post_states,
        chained_call.program_id,
    ) {
        panic!(
            "Invalid program behavior in program {:?}: {err}",
            chained_call.program_id
        );
    }
}

fn build_private_pda_npk_map(
    account_identities: &[InputAccountIdentity],
) -> HashMap<usize, (NullifierPublicKey, Identifier)> {
    account_identities
        .iter()
        .enumerate()
        .filter_map(|(pos, identity)| {
            identity
                .npk_if_private_pda()
                .map(|(npk, identifier)| (pos, (npk, identifier)))
        })
        .collect()
}

fn intersect_validity_windows(
    program_outputs: &[ProgramOutput],
) -> (BlockValidityWindow, TimestampValidityWindow) {
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

    let block_validity_window: BlockValidityWindow =
        (block_valid_from, block_valid_until).try_into().expect(
            "There should be non empty intersection in the program output block validity windows",
        );
    let timestamp_validity_window: TimestampValidityWindow = (ts_valid_from, ts_valid_until)
        .try_into()
        .expect(
            "There should be non empty intersection in the program output timestamp validity windows",
        );

    (block_validity_window, timestamp_validity_window)
}

/// Record or re-verify the `(program_id, seed) → account_id` family binding for the
/// transaction. Any claim or caller-seed authorization that resolves a `pre_state` under
/// `(program_id, seed)` must agree with every prior resolution of the same pair; otherwise a
/// single `pda_seeds: [seed]` entry could authorize multiple private-PDA family members at
/// once (different npks under the same seed) and let a callee mix balances across them. Free
/// function so callers can pass `&mut self.pda_family_binding` without holding a borrow on
/// the surrounding struct's other fields.
fn resolve_external_seed(
    account_identities: &[InputAccountIdentity],
    pre_state_position: usize,
    pre_account_id: AccountId,
    is_authorized: bool,
    private_pda_bound_positions: &mut HashMap<usize, (ProgramId, PdaSeed)>,
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
) {
    let external_seed = match account_identities.get(pre_state_position) {
        Some(InputAccountIdentity::PrivatePdaInit {
            npk,
            identifier,
            seed: Some((seed, authority_program_id)),
            ..
        }) => {
            let expected = AccountId::for_private_pda(authority_program_id, seed, npk, *identifier);
            assert_eq!(
                pre_account_id, expected,
                "External seed mismatch for PrivatePdaInit at position {pre_state_position}"
            );
            Some((*seed, *authority_program_id))
        }
        Some(InputAccountIdentity::PrivatePdaUpdate {
            nsk,
            identifier,
            seed: Some((seed, authority_program_id)),
            ..
        }) => {
            let npk = NullifierPublicKey::from(nsk);
            let expected =
                AccountId::for_private_pda(authority_program_id, seed, &npk, *identifier);
            assert_eq!(
                pre_account_id, expected,
                "External seed mismatch for PrivatePdaUpdate at position {pre_state_position}"
            );
            Some((*seed, *authority_program_id))
        }
        _ => None,
    };

    if let Some((seed, authority_program_id)) = external_seed {
        assert!(
            !is_authorized,
            "Private PDA with externally-provided seed must not be authorized at position {pre_state_position}"
        );
        bind_private_pda_position(
            private_pda_bound_positions,
            pre_state_position,
            authority_program_id,
            seed,
        );
        assert_family_binding(
            pda_family_binding,
            authority_program_id,
            seed,
            pre_account_id,
        );
    }
}

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

/// Resolve the authorization state of a `pre_state` seen again in a chained call and record
/// any resulting bindings. Returns `true` if the `pre_state` is authorized through either a
/// previously-seen authorization or a matching caller seed (under the public or private
/// derivation). When a caller seed matches, also records the `(caller, seed) → account_id`
/// family binding and, for the private form, marks the position in
/// `private_pda_bound_positions`. Only reachable when `caller_program_id.is_some()`,
/// top-level flows have no caller-emitted seeds, so binding at top level must come from the
/// claim path. Free function so callers can pass individual `&mut self.*` field borrows
/// without holding a borrow on the surrounding struct's other fields.
#[expect(
    clippy::too_many_arguments,
    reason = "breaking out a context struct does not buy us anything here"
)]
fn resolve_authorization_and_record_bindings(
    pda_family_binding: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    private_pda_bound_positions: &mut HashMap<usize, (ProgramId, PdaSeed)>,
    private_pda_npk_by_position: &HashMap<usize, (NullifierPublicKey, Identifier)>,
    authorized_accounts: &mut HashSet<AccountId>,
    pre_account_id: AccountId,
    pre_state_position: usize,
    caller_program_id: Option<ProgramId>,
    caller_pda_seeds: &[PdaSeed],
    previous_is_authorized: bool,
) -> bool {
    let matched_caller_seed: Option<(PdaSeed, bool, ProgramId)> =
        caller_program_id.and_then(|caller| {
            caller_pda_seeds.iter().find_map(|seed| {
                if AccountId::for_public_pda(&caller, seed) == pre_account_id {
                    return Some((*seed, false, caller));
                }
                if let Some((npk, identifier)) =
                    private_pda_npk_by_position.get(&pre_state_position)
                    && AccountId::for_private_pda(&caller, seed, npk, *identifier) == pre_account_id
                {
                    return Some((*seed, true, caller));
                }
                None
            })
        });

    if let Some((seed, is_private_form, caller)) = matched_caller_seed {
        assert_family_binding(pda_family_binding, caller, seed, pre_account_id);
        if is_private_form {
            bind_private_pda_position(
                private_pda_bound_positions,
                pre_state_position,
                caller,
                seed,
            );
        }
    }

    if authorized_accounts.contains(&pre_account_id) {
        return true;
    }

    let authorized = previous_is_authorized || matched_caller_seed.is_some();
    if authorized {
        authorized_accounts.insert(pre_account_id);
    }
    authorized
}
