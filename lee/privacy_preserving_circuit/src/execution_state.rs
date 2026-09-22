use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, ProgramImageClaim,
    PublicAction, WitnessKind,
    account::{AccountData, AccountId, ProgramShardSelector},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        AccountInput, BlockValidityWindow, CallKind, CallerData, ChainedCall,
        MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId, ProgramOutput, ShardStateDiff,
        TimestampValidityWindow, ValidityWindow, pre_states_match_shard_selectors,
        validate_execution,
    },
};
use risc0_zkvm::guest::env;

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    /// Maps private account IDs to their indices in `private_witnesses`.
    witness_by_account: HashMap<AccountId, usize>,
    /// Current account data with all the shards seen so far.
    post_states: HashMap<AccountId, AccountData>,
    /// Shard selectors seen in program outputs.
    shard_selectors_seen: HashSet<ProgramShardSelector>,
    /// Public accounts in the order they were first seen.
    public_order: Vec<AccountId>,
    /// Public accounts' authorization and first observed states.
    public_pre_states: HashMap<AccountId, (bool, AccountData)>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Binds each (program, seed) pair to one account per transaction.
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        private_witnesses: &[PrivateWitness],
        program_account_id: AccountId,
        program_outputs: Vec<ProgramOutput>,
        initial_shard_selectors: &[ProgramShardSelector],
        program_image_claims: &[ProgramImageClaim],
    ) -> Self {
        // Untrusted claims supplied by the prover: `env::verify` needs a real image id, not an
        // arbitrary dispatch address. The circuit does not check these against real chain state —
        // the sequencer does that independently (`V03State::get_program_image_id`) before
        // accepting the proof, which fails naturally if a claim is a lie (the receipt's actually
        // committed bytes won't match the reconstructed output). See `ProgramImageClaim`.
        assert!(
            !program_image_claims
                .iter()
                .any(|claim| claim.account_id == NATIVE_TOKEN_PROGRAM_ID),
            "The native token program has no deployable bytecode to claim"
        );
        assert_eq!(
            initial_shard_selectors.iter().collect::<HashSet<_>>().len(),
            initial_shard_selectors.len(),
            "An account may select several shards, but never the same one twice"
        );
        let image_id_by_account_id: HashMap<AccountId, ProgramId> = program_image_claims
            .iter()
            .map(|claim| (claim.account_id, claim.image_id))
            .collect();

        let mut execution_state = Self {
            witness_by_account: HashMap::new(),
            post_states: HashMap::new(),
            shard_selectors_seen: HashSet::new(),
            public_order: Vec::new(),
            public_pre_states: HashMap::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            pda_family_binding: HashMap::new(),
        };

        // Index private witnesses and check their account bindings.
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

        // Make an initial call with top-level data.
        let initial_call = ChainedCall {
            program_account_id,
            instruction_data: first_output.instruction_data.clone(),
            shard_selectors: Vec::new(),
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

            let Some(reported_output) = program_outputs_iter.next() else {
                panic!("Insufficient program outputs for chained calls");
            };

            // Check that instruction data in chained call is the instruction data in program output
            assert_eq!(
                chained_call.instruction_data, reported_output.instruction_data,
                "Mismatched instruction data between chained call and program output"
            );

            let program_output = accepted_output(
                &chained_call,
                caller_data.account_id,
                initial_shard_selectors,
                &image_id_by_account_id,
                reported_output,
            );

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

            execution_state.intersect_validity_windows(&program_output);

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

        // Every initial shard selector must appear in a program output.
        for shard_selector in initial_shard_selectors {
            assert!(
                execution_state
                    .shard_selectors_seen
                    .contains(shard_selector),
                "initial shard selector {shard_selector:?} is missing from the final execution state"
            );
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
        for diff in state_diffs {
            let pre = &diff.pre_state;
            let account_id = pre.account_id;
            let shard_selector = ProgramShardSelector::from(pre);
            let witness = self
                .witness_by_account
                .get(&account_id)
                .map(|&index| &private_witnesses[index]);

            if self.post_states.contains_key(&account_id) {
                self.check_known_account_authorization(&caller, caller_pda_seeds, witness, pre);
            } else {
                self.journal_first_sight(&caller, caller_pda_seeds, witness, pre);
            }

            // Save each public shard's first observed state for the verifier.
            let (program_account_id, data) = &pre.shard;
            if self.shard_selectors_seen.insert(shard_selector) && witness.is_none() {
                self.post_states
                    .get_mut(&account_id)
                    .expect("the account got a post state at its first sight")
                    .set_shard(*program_account_id, data.clone());
                self.public_pre_states
                    .get_mut(&account_id)
                    .expect("a public account records its journal view at its first sight")
                    .1
                    .shards
                    .insert(*program_account_id, data.clone());
            }

            assert_eq!(
                self.post_states[&account_id].shard(*program_account_id),
                data,
                "Inconsistent pre-state shard data for account {account_id}",
            );

            // If an account it authorized, push it to the autorized set.
            if pre.is_authorized {
                authorized_output_accounts.push(account_id);
            }

            self.post_states
                .get_mut(&account_id)
                .expect("the account got a post state by its own check just above")
                .apply_diff(&diff);
        }

        let mut authorized_accounts = caller.authorized_accounts;
        authorized_accounts.extend(authorized_output_accounts);
        authorized_accounts
    }

    fn intersect_validity_windows(&mut self, output: &ProgramOutput) {
        self.block_validity_window =
            intersect(self.block_validity_window, output.block_validity_window);
        self.timestamp_validity_window = intersect(
            self.timestamp_validity_window,
            output.timestamp_validity_window,
        );
    }

    /// Initializes an account's state and checks its authorization.
    fn journal_first_sight(
        &mut self,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        witness: Option<&PrivateWitness>,
        pre: &AccountInput,
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
                }
                WitnessKind::Pda { .. } => {
                    let granted = private_seed_granted(caller, caller_pda_seeds, witness);
                    if let Some((program, seed)) = granted {
                        assert_family_binding(
                            &mut self.pda_family_binding,
                            program,
                            seed,
                            account_id,
                        );
                    }
                    assert_eq!(
                        pre.is_authorized,
                        granted.is_some()
                            || self.is_already_authorized(caller, account_id, Some(witness)),
                        "Inconsistent authorization for private PDA {account_id}"
                    );
                }
            }
            self.post_states
                .insert(account_id, witness.account.data.clone());
        } else {
            let granted = public_seed_granted(caller, caller_pda_seeds, account_id);
            if let Some((program, seed)) = granted {
                assert!(
                    pre.is_authorized,
                    "Caller-seeded public PDA must be declared authorized at first sight: {account_id}"
                );
                assert_family_binding(&mut self.pda_family_binding, program, seed, account_id);
            }
            self.post_states.insert(account_id, AccountData::default());
            self.public_order.push(account_id);
            self.public_pre_states.insert(
                account_id,
                (
                    // Public PDAs cannot sign, so their journal authorization is false.
                    granted.is_none() && pre.is_authorized,
                    AccountData::default(),
                ),
            );
        }
    }

    /// Checks authorization for a previously seen account.
    fn check_known_account_authorization(
        &mut self,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        witness: Option<&PrivateWitness>,
        pre: &AccountInput,
    ) {
        let account_id = pre.account_id;
        let granted = witness.map_or_else(
            || public_seed_granted(caller, caller_pda_seeds, account_id),
            |witness| private_seed_granted(caller, caller_pda_seeds, witness),
        );
        if let Some((program, seed)) = granted {
            assert_family_binding(&mut self.pda_family_binding, program, seed, account_id);
        }
        assert_eq!(
            pre.is_authorized,
            granted.is_some() || self.is_already_authorized(caller, account_id, witness),
            "Inconsistent authorization for account {account_id}",
        );
    }

    /// Whether the account is authorized by its credentials or an inherited caller grant.
    fn is_already_authorized(
        &self,
        caller: &CallerData,
        account_id: AccountId,
        witness: Option<&PrivateWitness>,
    ) -> bool {
        caller.authorized_accounts.contains(&account_id)
            || witness.map_or_else(
                || {
                    self.public_pre_states
                        .get(&account_id)
                        .is_some_and(|(is_authorized, _)| *is_authorized)
                },
                |witness| matches!(witness.kind, WitnessKind::Regular { ask: Some(_) }),
            )
    }

    #[cfg(test)]
    pub(crate) fn from_post_states(
        public: Vec<(AccountId, bool, AccountData, AccountData)>,
    ) -> Self {
        let mut state = Self {
            witness_by_account: HashMap::new(),
            post_states: HashMap::new(),
            shard_selectors_seen: HashSet::new(),
            public_order: Vec::new(),
            public_pre_states: HashMap::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            pda_family_binding: HashMap::new(),
        };
        for (account_id, is_authorized, pre, post_state) in public {
            state.post_states.insert(account_id, post_state);
            state.public_order.push(account_id);
            state
                .public_pre_states
                .insert(account_id, (is_authorized, pre));
        }
        state
    }

    /// Returns the validity windows, public actions, and final private account states.
    pub fn into_parts(
        self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        Vec<PublicAction>,
        HashMap<AccountId, AccountData>,
    ) {
        let Self {
            witness_by_account,
            mut post_states,
            shard_selectors_seen: _,
            public_order,
            mut public_pre_states,
            block_validity_window,
            timestamp_validity_window,
            pda_family_binding: _,
        } = self;

        let public_actions = public_order
            .into_iter()
            .map(|account_id| {
                let (is_authorized, pre) = public_pre_states
                    .remove(&account_id)
                    .expect("a journalled public account carries its first-sight view");
                // Keep the same shard keys in the pre- and post-states.
                let post = post_states
                    .get(&account_id)
                    .expect("a journalled public account has a post state")
                    .project(pre.shards.keys().copied());
                PublicAction {
                    account_id,
                    is_authorized,
                    pre,
                    post,
                }
            })
            .collect();

        post_states.retain(|account_id, _| witness_by_account.contains_key(account_id));

        (
            block_validity_window,
            timestamp_validity_window,
            public_actions,
            post_states,
        )
    }
}

fn accepted_output(
    chained_call: &ChainedCall,
    caller_account_id: Option<AccountId>,
    initial_shard_selectors: &[ProgramShardSelector],
    image_id_by_account_id: &HashMap<AccountId, ProgramId>,
    reported_output: ProgramOutput,
) -> ProgramOutput {
    let is_native = chained_call.program_account_id == NATIVE_TOKEN_PROGRAM_ID;
    // Check that the callee used the requested shard selectors.
    let scheduled = match caller_account_id {
        // If the call is top-level, nothing to check, unless the protocol itself runs it.
        None => is_native.then_some(initial_shard_selectors),
        // Else, match.
        Some(_) => Some(chained_call.shard_selectors.as_slice()),
    };
    if let Some(scheduled) = scheduled {
        assert!(
            pre_states_match_shard_selectors(scheduled, &reported_output.state_diffs),
            "Call ran on shard selectors it was not handed"
        );
    }

    if is_native {
        let pre_states: Vec<AccountInput> = reported_output
            .state_diffs
            .into_iter()
            .map(|diff| diff.pre_state)
            .collect();
        return native_token::execute(
            caller_account_id,
            &pre_states,
            &chained_call.instruction_data,
        )
        .unwrap_or_else(|err| panic!("Invalid native transfer: {err}"));
    }

    // Check that `reported_output` is consistent with the execution of the corresponding
    // program.
    let image_id = image_id_by_account_id
        .get(&chained_call.program_account_id)
        .copied()
        .expect("no image_id claim supplied for invoked program account");
    let program_output_frame = lee_core::to_borsh_frame(&reported_output);
    env::verify(image_id, &program_output_frame)
        .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
    reported_output
}

fn intersect<T: Copy + Ord>(
    window: ValidityWindow<T>,
    other: ValidityWindow<T>,
) -> ValidityWindow<T> {
    let from = [window.start(), other.start()].into_iter().flatten().max();
    let to = [window.end(), other.end()].into_iter().flatten().min();
    (from, to)
        .try_into()
        .expect("There should be non empty intersection in the program output validity windows")
}

/// Returns the witness's PDA binding if authorized by the caller's seeds.
fn private_seed_granted(
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    witness: &PrivateWitness,
) -> Option<(AccountId, PdaSeed)> {
    witness.pda_binding().filter(|&(program, seed)| {
        Some(program) == caller.account_id && caller_pda_seeds.contains(&seed)
    })
}

/// Returns the account's PDA binding if authorized by the caller's seeds.
fn public_seed_granted(
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    account_id: AccountId,
) -> Option<(AccountId, PdaSeed)> {
    let caller_account_id = caller.account_id?;
    caller_pda_seeds.iter().find_map(|seed| {
        (AccountId::for_public_pda(&caller_account_id, seed) == account_id)
            .then_some((caller_account_id, *seed))
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

#[cfg(test)]
mod tests {
    use lee_core::{account::Account, encryption::ViewingPublicKey};

    use super::*;

    const PROGRAM: AccountId = AccountId::new([0xA0; 32]);
    const OTHER_PROGRAM: AccountId = AccountId::new([1; 32]);
    const SEED: PdaSeed = PdaSeed::new([2; 32]);
    const OTHER_SEED: PdaSeed = PdaSeed::new([3; 32]);

    fn witness_with(kind: WitnessKind) -> PrivateWitness {
        PrivateWitness {
            account: Account::default(),
            vpk: ViewingPublicKey::from_seed(&[4; 32], &[5; 32]),
            random_seed: [6; 32],
            identifier: 0,
            kind,
            nullifier: NullifierWitness::Init {
                npk: NullifierPublicKey([7; 32]),
                commitment_root: [8; 32],
            },
        }
    }

    fn pda_witness() -> PrivateWitness {
        witness_with(WitnessKind::Pda {
            binding: (PROGRAM, SEED),
        })
    }

    fn caller(account_id: AccountId) -> CallerData {
        CallerData {
            account_id: Some(account_id),
            authorized_accounts: HashSet::new(),
        }
    }

    #[test]
    fn a_delegated_seed_grants_the_binding_that_names_its_caller() {
        assert_eq!(
            private_seed_granted(&caller(PROGRAM), &[OTHER_SEED, SEED], &pda_witness()),
            Some((PROGRAM, SEED))
        );
    }

    #[test]
    fn a_caller_other_than_the_bound_program_grants_nothing() {
        assert_eq!(
            private_seed_granted(&caller(OTHER_PROGRAM), &[SEED], &pda_witness()),
            None
        );
    }

    #[test]
    fn an_undelegated_seed_grants_nothing() {
        assert_eq!(
            private_seed_granted(&caller(PROGRAM), &[OTHER_SEED], &pda_witness()),
            None
        );
    }

    #[test]
    fn a_regular_witness_has_no_binding_to_grant() {
        let witness = witness_with(WitnessKind::Regular { ask: None });
        assert_eq!(
            private_seed_granted(&caller(PROGRAM), &[SEED], &witness),
            None
        );
    }

    fn native_row(seed: u8, is_authorized: bool, balance: u128) -> AccountInput {
        AccountInput::balance(AccountId::new([seed; 32]), is_authorized, balance)
    }

    fn native_selectors() -> Vec<ProgramShardSelector> {
        vec![
            ProgramShardSelector::balance(AccountId::new([1; 32])),
            ProgramShardSelector::balance(AccountId::new([2; 32])),
        ]
    }

    fn tampered_native_report(amount: u128) -> ProgramOutput {
        let instruction = borsh::to_vec(&native_token::Instruction::Transfer { amount })
            .expect("the instruction serializes");
        let forged_credit = native_token::encode_balance(9_999);
        ProgramOutput {
            self_account_id: AccountId::new([0xAA; 32]),
            caller_account_id: Some(AccountId::new([0xBB; 32])),
            call_kind: CallKind::Unknown(7),
            instruction_data: instruction,
            state_diffs: vec![
                ShardStateDiff::new(native_row(1, true, 100), forged_credit.clone()),
                ShardStateDiff::new(native_row(2, false, 0), forged_credit),
            ],
            chained_calls: vec![ChainedCall {
                program_account_id: AccountId::new([0xCC; 32]),
                shard_selectors: Vec::new(),
                instruction_data: Vec::new(),
                pda_seeds: Vec::new(),
            }],
            block_validity_window: (Some(1), Some(2)).try_into().expect("a valid window"),
            timestamp_validity_window: (Some(3), Some(4)).try_into().expect("a valid window"),
            events: vec![lee_core::program::ProgramEvent {
                selector: [1; 8],
                data: vec![2; 4],
            }],
        }
    }

    fn derive_native_root(
        report: ProgramOutput,
        selectors: &[ProgramShardSelector],
    ) -> ExecutionState {
        ExecutionState::derive_from_outputs(
            &[],
            native_token::NATIVE_TOKEN_PROGRAM_ID,
            vec![report],
            selectors,
            &[],
        )
    }

    #[test]
    fn a_native_call_takes_only_its_rows_from_the_report() {
        let (block_window, timestamp_window, public_actions, _private) =
            derive_native_root(tampered_native_report(30), &native_selectors()).into_parts();

        let balances: Vec<_> = public_actions
            .iter()
            .map(|action| action.post.balance())
            .collect();
        assert_eq!(balances, vec![Ok(70), Ok(30)]);
        assert_eq!(block_window.start(), None);
        assert_eq!(block_window.end(), None);
        assert_eq!(timestamp_window.start(), None);
        assert_eq!(timestamp_window.end(), None);
    }

    #[test]
    #[should_panic(expected = "Call ran on shard selectors it was not handed")]
    fn a_native_root_must_report_the_scheduled_selectors_in_order() {
        let mut selectors = native_selectors();
        selectors.reverse();

        drop(derive_native_root(tampered_native_report(30), &selectors));
    }

    #[test]
    #[should_panic(expected = "must be authorized exactly by its supplied credential")]
    fn a_native_call_refuses_authorization_the_witness_does_not_carry() {
        let witness = witness_with(WitnessKind::Regular { ask: None });
        let sender = witness.account_id();
        let recipient = AccountId::new([2; 32]);
        let mut report = tampered_native_report(30);
        report.state_diffs[0].pre_state = AccountInput::balance(sender, true, 100);
        report.state_diffs[1].pre_state = AccountInput::balance(recipient, false, 0);

        drop(ExecutionState::derive_from_outputs(
            &[witness],
            native_token::NATIVE_TOKEN_PROGRAM_ID,
            vec![report],
            &[
                ProgramShardSelector::balance(sender),
                ProgramShardSelector::balance(recipient),
            ],
            &[],
        ));
    }

    #[test]
    #[should_panic(expected = "never the same one twice")]
    fn a_root_may_not_be_handed_the_same_shard_twice() {
        let selector = ProgramShardSelector::balance(AccountId::new([1; 32]));

        drop(ExecutionState::derive_from_outputs(
            &[],
            AccountId::new([0xD0; 32]),
            vec![tampered_native_report(30)],
            &[selector, selector],
            &[],
        ));
    }

    #[test]
    #[should_panic(expected = "The native token program has no deployable bytecode to claim")]
    fn a_guest_image_claim_for_the_reserved_id_is_refused() {
        drop(ExecutionState::derive_from_outputs(
            &[],
            native_token::NATIVE_TOKEN_PROGRAM_ID,
            vec![tampered_native_report(30)],
            &native_selectors(),
            &[ProgramImageClaim {
                account_id: native_token::NATIVE_TOKEN_PROGRAM_ID,
                image_id: [7; 8],
            }],
        ));
    }
}
