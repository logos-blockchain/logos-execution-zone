use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use nssa_core::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT_HASH, EncryptionScheme, Identifier,
    PrivateAccountKind,
    MembershipProof, Nullifier, NullifierPublicKey, NullifierSecretKey,
    PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, SharedSecretKey,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    compute_digest_for_path,
    program::{
        AccountPostState, BlockValidityWindow, ChainedCall, Claim, DEFAULT_PROGRAM_ID,
        MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow,
        validate_execution,
    },
};
use risc0_zkvm::{guest::env, serde::to_vec};


/// State of the involved accounts before and after program execution.
struct ExecutionState {
    pre_states: Vec<AccountWithMetadata>,
    post_states: HashMap<AccountId, Account>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Positions (in `pre_states`) of mask-3 accounts whose supplied npk has been bound to
    /// their `AccountId` via a proven `AccountId::for_private_pda(program_id, seed, npk, identifier)`
    /// check.
    /// Two proof paths populate this set: a `Claim::Pda(seed)` in a program's `post_state` on
    /// that `pre_state`, or a caller's `ChainedCall.pda_seeds` entry matching that `pre_state`
    /// under the private derivation. Binding is an idempotent property, not an event: the same
    /// position can legitimately be bound through both paths in the same tx (e.g. a program
    /// claims a private PDA and then delegates it to a callee), and the set uses `contains`,
    /// not `assert!(insert)`. After the main loop, every mask-3 position must appear in this
    /// set; otherwise the npk is unbound and the circuit rejects.
    private_pda_bound_positions: HashMap<usize, PdaSeed>,
    /// Across the whole transaction, each `(program_id, seed)` pair may resolve to at most one
    /// `AccountId`. A seed under a program can derive a family of accounts, one public PDA and
    /// one private PDA per distinct npk. Without this check, a single `pda_seeds: [S]` entry in
    /// a chained call could authorize multiple family members at once (different npks under the
    /// same seed) and let a callee mix balances across them. Every claim and every
    /// caller-authorization resolution is recorded here, either as a new `(program, seed)` →
    /// `AccountId` entry or as an equality check against the existing one, making the rule: one
    /// `(program, seed)` → one account per tx.
    pda_family_binding: HashMap<(ProgramId, PdaSeed), AccountId>,
    /// Map from a mask-3 `pre_state`'s position in `visibility_mask` to the npk supplied for
    /// that position in `private_account_keys`. Built once in `derive_from_outputs` by walking
    /// `visibility_mask` in lock-step with `private_account_keys`, used later by the claim and
    /// caller-seeds authorization paths.
    private_pda_npk_by_position: HashMap<usize, NullifierPublicKey>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        visibility_mask: &[u8],
        private_account_keys: &[(NullifierPublicKey, Identifier, SharedSecretKey)],
        program_id: ProgramId,
        program_outputs: Vec<ProgramOutput>,
    ) -> Self {
        // Build position → npk map for mask-3 pre_states. `private_account_keys` is consumed in
        // pre_state order across all masks 1/2/3, so walk `visibility_mask` in lock-step. The
        // downstream `compute_circuit_output` also consumes the same iterator and its trailing
        // assertions catch an over-supply of keys; under-supply surfaces here.
        let mut private_pda_npk_by_position: HashMap<usize, NullifierPublicKey> = HashMap::new();
        {
            let mut keys_iter = private_account_keys.iter();
            for (pos, &mask) in visibility_mask.iter().enumerate() {
                if matches!(mask, 1..=3) {
                    let (npk, _, _) = keys_iter.next().unwrap_or_else(|| {
                        panic!(
                            "private_account_keys shorter than visibility_mask demands: no key for masked position {pos} (mask {mask})"
                        )
                    });
                    if mask == 3 {
                        private_pda_npk_by_position.insert(pos, *npk);
                    }
                }
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
            private_pda_npk_by_position,
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
                program_output.caller_program_id, caller_program_id,
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

            for next_call in program_output.chained_calls.iter().rev() {
                chained_calls.push_front((next_call.clone(), Some(chained_call.program_id)));
            }

            execution_state.validate_and_sync_states(
                visibility_mask,
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

        // Every mask-3 pre_state must have had its npk bound to its account_id, either via a
        // `Claim::Pda(seed)` in some program's post_state or via a caller's `pda_seeds` matching
        // the private derivation. An unbound mask-3 pre_state has no cryptographic link between
        // the supplied npk and the account_id, and must be rejected.
        for (pos, &mask) in visibility_mask.iter().enumerate() {
            if mask == 3 {
                assert!(
                    execution_state.private_pda_bound_positions.contains_key(&pos),
                    "private PDA pre_state at position {pos} has no proven (seed, npk) binding via Claim::Pda or caller pda_seeds"
                );
            }
        }

        // Check that all modified uninitialized accounts were claimed
        for (account_id, post) in execution_state
            .pre_states
            .iter()
            .filter(|a| a.account.program_owner == DEFAULT_PROGRAM_ID)
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
                post.program_owner, DEFAULT_PROGRAM_ID,
                "Account {account_id} was modified but not claimed"
            );
        }

        execution_state
    }

    /// Validate program pre and post states and populate the execution state.
    fn validate_and_sync_states(
        &mut self,
        visibility_mask: &[u8],
        program_id: ProgramId,
        caller_program_id: Option<ProgramId>,
        caller_pda_seeds: &[PdaSeed],
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountPostState>,
    ) {
        for (pre, mut post) in pre_states.into_iter().zip(post_states) {
            let pre_account_id = pre.account_id;
            let pre_is_authorized = pre.is_authorized;
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

                    let (previous_is_authorized, pre_state_position) = self
                        .pre_states
                        .iter()
                        .enumerate()
                        .find(|(_, acc)| acc.account_id == pre_account_id)
                        .map_or_else(
                            || panic!(
                                "Pre state must exist in execution state for account {pre_account_id}",
                            ),
                            |(pos, acc)| (acc.is_authorized, pos)
                        );

                    let is_authorized = resolve_authorization_and_record_bindings(
                        &mut self.pda_family_binding,
                        &mut self.private_pda_bound_positions,
                        &self.private_pda_npk_by_position,
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
                }
                Entry::Vacant(_) => {
                    // Pre state for the initial call
                    self.pre_states.push(pre);
                }
            }

            if let Some(claim) = post.required_claim() {
                // The invoked program can only claim accounts with default program id.
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

                let mask = visibility_mask[pre_state_position];
                match mask {
                    0 => match claim {
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
                    },
                    3 => {
                        match claim {
                            Claim::Authorized => {
                                assert!(
                                    pre_is_authorized,
                                    "Cannot claim unauthorized private PDA {pre_account_id}"
                                );
                            }
                            Claim::Pda(seed) => {
                                let npk = self
                                .private_pda_npk_by_position
                                .get(&pre_state_position)
                                .expect("private PDA pre_state must have an npk in the position map");
                                let pda = AccountId::for_private_pda(&program_id, &seed, npk, u128::MAX);
                                assert_eq!(
                                    pre_account_id, pda,
                                    "Invalid private PDA claim for account {pre_account_id}"
                                );
                                self.private_pda_bound_positions.insert(pre_state_position, seed);
                                assert_family_binding(
                                    &mut self.pda_family_binding,
                                    program_id,
                                    seed,
                                    pre_account_id,
                                );
                            }
                        }
                    }
                    _ => {
                        // Mask 1/2: standard private accounts don't enforce the claim semantics.
                        // Unauthorized private claiming is intentionally allowed since operating
                        // these accounts requires the npk/nsk keypair anyway.
                    }
                }

                post.account_mut().program_owner = program_id;
            }

            post_states_entry.insert_entry(post.into_account());
        }
    }

    /// Get an iterator over pre and post states of each account involved in the execution.
    pub fn into_states_iter(
        mut self,
    ) -> impl ExactSizeIterator<Item = (AccountWithMetadata, Account)> {
        self.pre_states.into_iter().map(move |pre| {
            let post = self
                .post_states
                .remove(&pre.account_id)
                .expect("Account from pre states should exist in state diff");
            (pre, post)
        })
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
    private_pda_bound_positions: &mut HashMap<usize, PdaSeed>,
    private_pda_npk_by_position: &HashMap<usize, NullifierPublicKey>,
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
                if let Some(npk) = private_pda_npk_by_position.get(&pre_state_position)
                    && AccountId::for_private_pda(&caller, seed, npk, u128::MAX) == pre_account_id
                {
                    return Some((*seed, true, caller));
                }
                None
            })
        });

    if let Some((seed, is_private_form, caller)) = matched_caller_seed {
        assert_family_binding(pda_family_binding, caller, seed, pre_account_id);
        if is_private_form {
            private_pda_bound_positions.insert(pre_state_position, seed);
        }
    }

    previous_is_authorized || matched_caller_seed.is_some()
}

fn compute_circuit_output(
    execution_state: ExecutionState,
    visibility_mask: &[u8],
    private_account_keys: &[(NullifierPublicKey, Identifier, SharedSecretKey)],
    private_account_nsks: &[NullifierSecretKey],
    private_account_membership_proofs: &[Option<MembershipProof>],
) -> PrivacyPreservingCircuitOutput {
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        ciphertexts: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        block_validity_window: execution_state.block_validity_window,
        timestamp_validity_window: execution_state.timestamp_validity_window,
    };

    let states_iter = execution_state.into_states_iter();
    assert_eq!(
        visibility_mask.len(),
        states_iter.len(),
        "Invalid visibility mask length"
    );

    let mut private_keys_iter = private_account_keys.iter();
    let mut private_nsks_iter = private_account_nsks.iter();
    let mut private_membership_proofs_iter = private_account_membership_proofs.iter();

    let mut output_index = 0;
    for (account_visibility_mask, (pre_state, post_state)) in
        visibility_mask.iter().copied().zip(states_iter)
    {
        match account_visibility_mask {
            0 => {
                // Public account
                output.public_pre_states.push(pre_state);
                output.public_post_states.push(post_state);
            }
            1 | 2 => {
                let Some((npk, identifier, shared_secret)) = private_keys_iter.next() else {
                    panic!("Missing private account key");
                };
                let account_id = AccountId::from((npk, *identifier));

                assert_eq!(account_id, pre_state.account_id, "AccountId mismatch");

                let (new_nullifier, new_nonce) = if account_visibility_mask == 1 {
                    // Private account with authentication

                    let Some(nsk) = private_nsks_iter.next() else {
                        panic!("Missing private account nullifier secret key");
                    };

                    // Verify the nullifier public key
                    assert_eq!(
                        npk,
                        &NullifierPublicKey::from(nsk),
                        "Nullifier public key mismatch"
                    );

                    // Check pre_state authorization
                    assert!(
                        pre_state.is_authorized,
                        "Pre-state not authorized for authenticated private account"
                    );

                    let Some(membership_proof_opt) = private_membership_proofs_iter.next() else {
                        panic!("Missing membership proof");
                    };

                    let new_nullifier = compute_nullifier_and_set_digest(
                        membership_proof_opt.as_ref(),
                        &pre_state.account,
                        &account_id,
                        nsk,
                    );

                    let new_nonce = pre_state.account.nonce.private_account_nonce_increment(nsk);

                    (new_nullifier, new_nonce)
                } else {
                    // Private account without authentication

                    assert_eq!(
                        pre_state.account,
                        Account::default(),
                        "Found new private account with non default values",
                    );

                    assert!(
                        !pre_state.is_authorized,
                        "Found new private account marked as authorized."
                    );

                    let Some(membership_proof_opt) = private_membership_proofs_iter.next() else {
                        panic!("Missing membership proof");
                    };

                    assert!(
                        membership_proof_opt.is_none(),
                        "Membership proof must be None for unauthorized accounts"
                    );

                    let nullifier = Nullifier::for_account_initialization(&account_id);

                    let new_nonce = Nonce::private_account_nonce_init(&account_id);

                    ((nullifier, DUMMY_COMMITMENT_HASH), new_nonce)
                };
                output.new_nullifiers.push(new_nullifier);

                // Update post-state with new nonce
                let mut post_with_updated_nonce = post_state;
                post_with_updated_nonce.nonce = new_nonce;

                // Compute commitment
                let commitment_post = Commitment::new(&account_id, &post_with_updated_nonce);

                // Encrypt and push post state
                let encrypted_account = EncryptionScheme::encrypt(
                    &post_with_updated_nonce,
                    &PrivateAccountKind::Account(*identifier),
                    shared_secret,
                    &commitment_post,
                    output_index,
                );

                output.new_commitments.push(commitment_post);
                output.ciphertexts.push(encrypted_account);
                output_index = output_index
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("Too many private accounts, output index overflow"));
            }
            3 => {
                // Private PDA account. The supplied npk has already been bound to
                // `pre_state.account_id` upstream in `validate_and_sync_states`, either via a
                // `Claim::Pda(seed)` match or via a caller `pda_seeds` match, both of which
                // assert `AccountId::for_private_pda(owner, seed, npk, identifier) == account_id`. The
                // post-loop assertion in `derive_from_outputs` (see the
                // `private_pda_bound_positions` check) guarantees that every mask-3
                // position has been through at least one such binding, so this
                // branch can safely use the wallet npk without re-verifying.
                let Some((npk, identifier, shared_secret)) = private_keys_iter.next() else {
                    panic!("Missing private account key");
                };

                let (new_nullifier, new_nonce) = if pre_state.is_authorized {
                    // Existing private PDA with authentication (like mask 1)
                    let Some(nsk) = private_nsks_iter.next() else {
                        panic!("Missing private account nullifier secret key");
                    };
                    assert_eq!(
                        npk,
                        &NullifierPublicKey::from(nsk),
                        "Nullifier public key mismatch"
                    );

                    let Some(membership_proof_opt) = private_membership_proofs_iter.next() else {
                        panic!("Missing membership proof");
                    };

                    let new_nullifier = compute_nullifier_and_set_digest(
                        membership_proof_opt.as_ref(),
                        &pre_state.account,
                        &pre_state.account_id,
                        nsk,
                    );
                    let new_nonce = pre_state.account.nonce.private_account_nonce_increment(nsk);
                    (new_nullifier, new_nonce)
                } else {
                    // New private PDA (like mask 2). The default + unauthorized requirement
                    // here rules out use cases like a fully-private multisig, which would need
                    // a non-default, non-authorized private PDA input account.
                    // TODO(private-pdas-pr-2/3): relax this once the wallet can supply a
                    // `(seed, owner)` side input so the npk-to-account_id binding can be
                    // re-verified for an existing private PDA without a `Claim::Pda` or caller
                    // `pda_seeds` match.
                    assert_eq!(
                        pre_state.account,
                        Account::default(),
                        "New private PDA must be default"
                    );

                    let Some(membership_proof_opt) = private_membership_proofs_iter.next() else {
                        panic!("Missing membership proof");
                    };
                    assert!(
                        membership_proof_opt.is_none(),
                        "Membership proof must be None for new accounts"
                    );

                    let nullifier = Nullifier::for_account_initialization(&pre_state.account_id);
                    let new_nonce = Nonce::private_account_nonce_init(&pre_state.account_id);
                    ((nullifier, DUMMY_COMMITMENT_HASH), new_nonce)
                };
                output.new_nullifiers.push(new_nullifier);

                let mut post_with_updated_nonce = post_state;
                post_with_updated_nonce.nonce = new_nonce;

                let commitment_post =
                    Commitment::new(&pre_state.account_id, &post_with_updated_nonce);

                let encrypted_account = EncryptionScheme::encrypt(
                    &post_with_updated_nonce,
                    &PrivateAccountKind::Account(*identifier),
                    shared_secret,
                    &commitment_post,
                    output_index,
                );

                output.new_commitments.push(commitment_post);
                output.ciphertexts.push(encrypted_account);
                output_index = output_index
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("Too many private accounts, output index overflow"));
            }
            _ => panic!("Invalid visibility mask value"),
        }
    }

    assert!(
        private_keys_iter.next().is_none(),
        "Too many private account keys"
    );

    assert!(
        private_nsks_iter.next().is_none(),
        "Too many private account nullifier secret keys"
    );

    assert!(
        private_membership_proofs_iter.next().is_none(),
        "Too many private account membership proofs"
    );

    output
}

fn compute_nullifier_and_set_digest(
    membership_proof_opt: Option<&MembershipProof>,
    pre_account: &Account,
    account_id: &AccountId,
    nsk: &NullifierSecretKey,
) -> (Nullifier, CommitmentSetDigest) {
    membership_proof_opt.as_ref().map_or_else(
        || {
            assert_eq!(
                *pre_account,
                Account::default(),
                "Found new private account with non default values"
            );

            // Compute initialization nullifier
            let nullifier = Nullifier::for_account_initialization(account_id);
            (nullifier, DUMMY_COMMITMENT_HASH)
        },
        |membership_proof| {
            // Compute commitment set digest associated with provided auth path
            let commitment_pre = Commitment::new(account_id, pre_account);
            let set_digest = compute_digest_for_path(&commitment_pre, membership_proof);

            // Compute update nullifier
            let nullifier = Nullifier::for_account_update(&commitment_pre, nsk);
            (nullifier, set_digest)
        },
    )
}

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        visibility_mask,
        private_account_keys,
        private_account_nsks,
        private_account_membership_proofs,
        program_id,
    } = env::read();

    let execution_state = ExecutionState::derive_from_outputs(
        &visibility_mask,
        &private_account_keys,
        program_id,
        program_outputs,
    );

    let output = compute_circuit_output(
        execution_state,
        &visibility_mask,
        &private_account_keys,
        &private_account_nsks,
        &private_account_membership_proofs,
    );

    env::commit(&output);
}
