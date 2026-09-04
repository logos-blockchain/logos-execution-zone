use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    Identifier, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness,
    ProgramImageClaim, PublicAction, WitnessKind,
    account::{Account, AccountId, AccountView, Input, Position},
    encryption::ViewingPublicKey,
    program::{
        BlockValidityWindow, CallKind, CallerData, ChainedCall, MAX_NUMBER_CHAINED_CALLS, PdaSeed,
        ProgramId, ProgramOutput, ShardStateDiff, TimestampValidityWindow, post_state,
        pre_states_match_positions, validate_execution,
    },
};
use risc0_zkvm::guest::env;

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    /// Where each private account's witness sits in `private_witnesses`, keyed by the address that
    /// witness derives. A position is private exactly when its account is in here; nothing else
    /// marks one.
    witness_by_account: HashMap<AccountId, usize>,
    /// The running state of every sighted account: a private one starts as its whole committed
    /// witness account, a public one as the balance the guest was handed, gaining a shard at each
    /// namespace's first sight.
    tracked: HashMap<AccountId, Account>,
    /// The `(account, namespace)` pairs already sighted. A first sighting is anchored to chain
    /// state and journalled; a later one is anchored to what an earlier frame wrote.
    journalled: HashSet<Position>,
    /// Public accounts in first-sight order, so the journal the verifier replays is deterministic.
    public_order: Vec<AccountId>,
    /// Each public account's journalled authorization and the first-sight view the verifier
    /// anchors against chain state.
    public_pre: HashMap<AccountId, (bool, AccountView)>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Accounts declared authorized at their first sight, anywhere in the call tree.
    /// Authorization is monotone: they remain authorized throughout all calls.
    globally_authorized: HashSet<AccountId>,
    /// Across the whole transaction each `(program, seed)` resolves to at most one account, so
    /// one delegated seed cannot authorize several members of the same PDA family.
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        private_witnesses: &[PrivateWitness],
        program_account_id: AccountId,
        program_outputs: Vec<ProgramOutput>,
        initial_positions: &[Position],
        program_image_claims: &[ProgramImageClaim],
    ) -> Self {
        // Untrusted claims supplied by the prover: `env::verify` needs a real image id, not an
        // arbitrary dispatch address. The circuit does not check these against real chain state —
        // the sequencer does that independently (`V03State::get_program_image_id`) before
        // accepting the proof, which fails naturally if a claim is a lie (the receipt's actually
        // committed bytes won't match the reconstructed output). See `ProgramImageClaim`.
        let image_id_by_account_id: HashMap<AccountId, ProgramId> = program_image_claims
            .iter()
            .map(|claim| (claim.account_id, claim.image_id))
            .collect();

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
            witness_by_account: HashMap::new(),
            tracked: HashMap::new(),
            journalled: HashSet::new(),
            public_order: Vec::new(),
            public_pre: HashMap::new(),
            block_validity_window,
            timestamp_validity_window,
            globally_authorized: HashSet::new(),
            pda_family_binding: HashMap::new(),
        };

        // The witness is the only link between a private address and the keys that open it, so
        // every derivation it claims is proven here, once per witness, before any position is
        // resolved against it.
        for (index, witness) in private_witnesses.iter().enumerate() {
            let account_id = witness.account_id();
            let duplicate = execution_state
                .witness_by_account
                .insert(account_id, index)
                .is_some();
            assert!(
                !duplicate,
                "Two witnesses derive the same private account {account_id}"
            );
            match &witness.kind {
                WitnessKind::Pda {
                    binding: (program, seed),
                } => assert_family_binding(
                    &mut execution_state.pda_family_binding,
                    *program,
                    *seed,
                    account_id,
                ),
                WitnessKind::Regular { ask } => {
                    if let Some(ask) = ask {
                        let derived = NullifierSecretKey::from(ask);
                        match &witness.nullifier {
                            // Check that the authorization key is actually bound to the
                            // account Id.
                            NullifierWitness::Update { nsk, .. } => assert_eq!(
                                derived, *nsk,
                                "Authorization secret key does not derive the nullifier secret key of {account_id}"
                            ),
                            NullifierWitness::Init { npk, .. } => assert_eq!(
                                NullifierPublicKey::from(&derived),
                                *npk,
                                "Authorization secret key does not derive the nullifier public key of {account_id}"
                            ),
                        }
                    }
                }
            }
        }

        let Some(first_output) = program_outputs.first() else {
            panic!("No program outputs provided");
        };

        // `positions` is never read below (every check uses `program_output` instead) — this
        // synthetic call only bootstraps the loop's first iteration.
        let initial_call = ChainedCall {
            program_account_id,
            instruction_data: first_output.instruction_data.clone(),
            positions: first_output
                .state_diffs
                .iter()
                .map(|diff| Position::from(&diff.pre))
                .collect(),
            pda_seeds: Vec::new(),
        };
        let initial_caller_data = CallerData {
            account_id: None,
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

            // Check the positions used are exactly those the call was performed with.
            assert!(
                // If the call is top-level, nothing to check.
                caller_data.account_id.is_none()
                    // Else, match.
                    || pre_states_match_positions(
                        &chained_call.positions,
                        &program_output
                            .state_diffs
                            .iter()
                            .map(|diff| diff.pre.clone())
                            .collect::<Vec<_>>()
                    ),
                "Callee ran on positions the chained call did not name"
            );

            // Check that `program_output` is consistent with the execution of the corresponding
            // program. `env::verify` needs the invoked program's real image id, not its dispatch
            // address — resolved from the prover-supplied (and independently, externally
            // verified) claims. See `ProgramImageClaim`.
            let image_id = image_id_by_account_id
                .get(&chained_call.program_account_id)
                .copied()
                .expect("no image_id claim supplied for invoked program account");
            let program_output_frame = lee_core::to_borsh_frame(&program_output);
            env::verify(image_id, &program_output_frame).unwrap_or_else(|_: Infallible| {
                unreachable!("Infallible error is never constructed")
            });

            // Verify that the program output's self_account_id matches the expected program ID.
            // This ensures the proof commits to which program produced the output.
            assert_eq!(
                program_output.self_account_id, chained_call.program_account_id,
                "Program output self_account_id does not match chained call program_account_id"
            );

            // Verify that the program output's caller_account_id matches the actual caller.
            // This prevents a malicious user from privately executing an internal function
            // by spoofing caller_account_id (e.g. passing caller_account_id = self_account_id
            // to bypass access control checks).
            assert_eq!(
                program_output.caller_account_id, caller_data.account_id,
                "Program output caller_account_id does not match actual caller"
            );

            // Only a top-level call may legitimately be a no-op; a chained call must execute.
            if caller_data.account_id.is_some() {
                assert_eq!(
                    program_output.call_kind,
                    CallKind::Execute,
                    "Chained call to {:?} did not execute",
                    chained_call.program_account_id
                );
            }

            // Check that the program is well behaved.
            // See the # Programs section for the definition of the `validate_execution` method.
            let validated_execution =
                validate_execution(&program_output.state_diffs, chained_call.program_account_id);
            if let Err(err) = validated_execution {
                panic!(
                    "Invalid program behavior in program {:?}: {err}",
                    chained_call.program_account_id
                );
            }

            let authorized_accounts = execution_state.validate_and_sync_states(
                caller_data,
                &chained_call.pda_seeds,
                program_output.state_diffs,
                private_witnesses,
            );

            for next_call in program_output.chained_calls.into_iter().rev() {
                // Push the call with newly-authorized account set.
                chained_calls.push_front((
                    next_call,
                    CallerData {
                        account_id: Some(chained_call.program_account_id),
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

        // Nothing the top-level call was actually invoked with may vanish from a chained call's
        // own output — a program can't silently drop a position it was handed.
        for position in initial_positions {
            assert!(
                execution_state.journalled.contains(position),
                "initial position {position:?} is missing from the final execution state"
            );
        }

        // A witness names an account to spend and re-create. One the tree never touched has no
        // state to carry into its note, so the input is malformed.
        if let Some(account_id) = execution_state
            .witness_by_account
            .keys()
            .find(|account_id| !execution_state.tracked.contains_key(*account_id))
        {
            panic!("Private witness for {account_id} was never touched by the execution");
        }

        execution_state
    }

    /// Validate program pre and post states and populate the execution state.
    ///
    /// Return the set of authorized accounts as the result of the processed
    /// call.
    fn validate_and_sync_states(
        &mut self,
        caller: CallerData,
        caller_pda_seeds: &[PdaSeed],
        state_diffs: Vec<ShardStateDiff>,
        private_witnesses: &[PrivateWitness],
    ) -> HashSet<AccountId> {
        let mut authorized_output_accounts = Vec::new();
        // Two passes, mirroring the public path: every pre state is checked against the state as
        // of the PREVIOUS frame before any of this frame's posts land. `validate_execution` has
        // already rejected two positions naming the same account, and one account may
        // legitimately be re-sighted under another namespace by a later call.
        for diff in &state_diffs {
            let pre = &diff.pre;
            let account_id = pre.account_id;
            let position = Position::from(pre);
            let witness = self
                .witness_by_account
                .get(&account_id)
                .map(|&index| &private_witnesses[index]);

            if self.tracked.contains_key(&account_id) {
                self.check_known_account(&caller, caller_pda_seeds, witness, pre);
            } else {
                self.journal_first_sight(&caller, caller_pda_seeds, witness, pre);
            }

            // A namespace first sighted on a public account is trusted and journalled here: the
            // verifier is what anchors it against chain state. A private account needs nothing
            // recorded — its witness already carries every namespace it holds.
            if self.journalled.insert(position)
                && witness.is_none()
                && let Some((namespace, data)) = &pre.shard
            {
                self.tracked
                    .get_mut(&account_id)
                    .expect("the account was tracked at its first sight")
                    .set_shard(*namespace, data.clone());
                self.public_pre
                    .get_mut(&account_id)
                    .expect("a public account records its journal view at its first sight")
                    .1
                    .shards
                    .insert(*namespace, data.clone());
            }

            assert_eq!(
                Input::at(position, pre.is_authorized, &self.tracked[&account_id]),
                *pre,
                "Inconsistent pre state for account {account_id}",
            );

            // If an account it authorized, push it to the autorized set.
            if pre.is_authorized {
                authorized_output_accounts.push(account_id);
            }
        }

        for diff in state_diffs {
            let post = post_state(&diff).expect("validate_execution checked the balance diff");
            self.tracked
                .get_mut(&diff.pre.account_id)
                .expect("every position of this call was tracked by the first pass")
                .splice(Position::from(&diff.pre), post);
        }

        let mut authorized_accounts = caller.authorized_accounts;
        authorized_accounts.extend(authorized_output_accounts);
        authorized_accounts
    }

    /// An account seen for the first time. Nothing in this tree has written it yet, so its state
    /// enters the tracker here: from the committed witness for a private account, from the guest's
    /// own view for a public one, where the verifier is what anchors the journalled entry.
    fn journal_first_sight(
        &mut self,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        witness: Option<&PrivateWitness>,
        pre: &Input,
    ) {
        let account_id = pre.account_id;
        if let Some(witness) = witness {
            match &witness.kind {
                WitnessKind::Regular { ask } => {
                    assert_eq!(
                        pre.is_authorized,
                        ask.is_some(),
                        "Regular private account {account_id} must be authorized exactly by its supplied credential"
                    );
                    if pre.is_authorized {
                        self.globally_authorized.insert(account_id);
                    }
                }
                WitnessKind::Pda { .. } => {
                    let granted = seed_granted(
                        caller,
                        caller_pda_seeds,
                        account_id,
                        private_pda_keys(witness),
                    );
                    if let Some((program, seed)) = granted {
                        assert_family_binding(
                            &mut self.pda_family_binding,
                            program,
                            seed,
                            account_id,
                        );
                    }
                    // Authorization is a property of the ACCOUNT, so its first sight inherits what
                    // the tree already established — exactly as the public path does, which draws
                    // no first-sight/repeat distinction at all.
                    assert_eq!(
                        pre.is_authorized,
                        granted.is_some() || self.is_already_authorized(caller, account_id),
                        "Inconsistent authorization for private PDA {account_id}"
                    );
                }
            }
            self.tracked.insert(account_id, witness.account.clone());
        } else {
            let granted = seed_granted(caller, caller_pda_seeds, account_id, None);
            match granted {
                Some((program, seed)) => {
                    assert!(
                        pre.is_authorized,
                        "Caller-seeded public PDA must be declared authorized at first sight: {account_id}"
                    );
                    assert_family_binding(&mut self.pda_family_binding, program, seed, account_id);
                }
                None => {
                    if pre.is_authorized {
                        self.globally_authorized.insert(account_id);
                    }
                }
            }
            self.tracked.insert(
                account_id,
                Account {
                    balance: pre.balance,
                    ..Account::default()
                },
            );
            self.public_order.push(account_id);
            self.public_pre.insert(
                account_id,
                (
                    // The verifier re-derives a public account's authorization from the signer
                    // set, where a keyless PDA can never appear, so the
                    // journal must report the credential the account has, not
                    // the grant that reached it.
                    granted.is_none() && pre.is_authorized,
                    AccountView {
                        balance: pre.balance,
                        ..AccountView::default()
                    },
                ),
            );
        }
    }

    /// An account an earlier frame already sighted. Its state is anchored to what that frame left
    /// behind rather than to chain state, and its authorization is checked here against what this
    /// tree already established.
    fn check_known_account(
        &mut self,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        witness: Option<&PrivateWitness>,
        pre: &Input,
    ) {
        let account_id = pre.account_id;
        let granted = seed_granted(
            caller,
            caller_pda_seeds,
            account_id,
            witness.and_then(private_pda_keys),
        );
        if let Some((program, seed)) = granted {
            assert_family_binding(&mut self.pda_family_binding, program, seed, account_id);
        }
        assert_eq!(
            pre.is_authorized,
            granted.is_some() || self.is_already_authorized(caller, account_id),
            "Inconsistent authorization for account {account_id}",
        );
    }

    /// Whether the tree has already established this account's authorization — by a grant that
    /// reached it, or by a credential recorded at its first sight. Subtree-scoped through
    /// `caller.authorized_accounts`, exactly like the public path's inherited set.
    fn is_already_authorized(&self, caller: &CallerData, account_id: AccountId) -> bool {
        self.globally_authorized.contains(&account_id)
            || caller.authorized_accounts.contains(&account_id)
    }

    /// The state a completed call tree leaves behind, built directly. Lets the output stage be
    /// tested against the host without a guest ELF to replay the tree through.
    #[cfg(test)]
    pub(crate) fn from_tracked(
        public: Vec<(AccountId, bool, AccountView, Account)>,
        private: Vec<(AccountId, Account)>,
    ) -> Self {
        let mut state = Self {
            witness_by_account: HashMap::new(),
            tracked: HashMap::new(),
            journalled: HashSet::new(),
            public_order: Vec::new(),
            public_pre: HashMap::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            globally_authorized: HashSet::new(),
            pda_family_binding: HashMap::new(),
        };
        for (account_id, is_authorized, pre, tracked) in public {
            state.tracked.insert(account_id, tracked);
            state.public_order.push(account_id);
            state.public_pre.insert(account_id, (is_authorized, pre));
        }
        for (index, (account_id, tracked)) in private.into_iter().enumerate() {
            state.tracked.insert(account_id, tracked);
            state.witness_by_account.insert(account_id, index);
        }
        state
    }

    /// Consume self and yield the validity windows, one public action per public account in
    /// first-sight order, and the final state of every private account keyed by its address.
    /// Returning everything together keeps the fields module-private rather than forcing them
    /// visible to downstream consumers.
    pub fn into_parts(
        self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        Vec<PublicAction>,
        HashMap<AccountId, Account>,
    ) {
        let Self {
            witness_by_account,
            mut tracked,
            journalled: _,
            public_order,
            mut public_pre,
            block_validity_window,
            timestamp_validity_window,
            globally_authorized: _,
            pda_family_binding: _,
        } = self;

        let public_actions = public_order
            .into_iter()
            .map(|account_id| {
                let (is_authorized, pre) = public_pre
                    .remove(&account_id)
                    .expect("a journalled public account carries its first-sight view");
                // The journal reports the namespaces the transaction touched and no others: an
                // untouched one is the verifier's to leave alone.
                let post = tracked
                    .get(&account_id)
                    .expect("a journalled public account is tracked")
                    .project(pre.shards.keys().copied());
                PublicAction {
                    account_id,
                    is_authorized,
                    pre,
                    post,
                }
            })
            .collect();

        tracked.retain(|account_id, _| witness_by_account.contains_key(account_id));

        (
            block_validity_window,
            timestamp_validity_window,
            public_actions,
            tracked,
        )
    }
}

/// The keys a private PDA's address is derived from, so a caller's seeds can be matched against
/// the private derivation. `None` for any other witness — no other address is caller-derivable.
fn private_pda_keys(
    witness: &PrivateWitness,
) -> Option<(NullifierPublicKey, &ViewingPublicKey, Identifier)> {
    match witness.kind {
        WitnessKind::Pda { .. } => {
            Some((witness.nullifier.npk(), &witness.vpk, witness.identifier))
        }
        WitnessKind::Regular { .. } => None,
    }
}

/// A caller may delegate its own PDAs to this callee by seed. That is the only way a keyless
/// address can be authorized, in either form: `keys` selects the private derivation, its absence
/// the public one.
fn seed_granted(
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    account_id: AccountId,
    keys: Option<(NullifierPublicKey, &ViewingPublicKey, Identifier)>,
) -> Option<(AccountId, PdaSeed)> {
    let caller_account_id = caller.account_id?;
    caller_pda_seeds.iter().find_map(|seed| {
        let derived = match keys {
            Some((npk, vpk, identifier)) => {
                AccountId::for_private_pda(&caller_account_id, seed, &npk, vpk, identifier)
            }
            None => AccountId::for_public_pda(&caller_account_id, seed),
        };
        (derived == account_id).then_some((caller_account_id, *seed))
    })
}

fn assert_family_binding(
    bindings: &mut HashMap<(AccountId, PdaSeed), AccountId>,
    program_account_id: AccountId,
    seed: PdaSeed,
    account_id: AccountId,
) {
    match bindings.entry((program_account_id, seed)) {
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
