use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, ProgramImageClaim,
    PublicAction, WitnessKind,
    account::{AccountData, AccountId, AccountInput, ProgramShardSelector},
    program::{
        AccountStateDiff, BlockValidityWindow, CallKind, CallerData, ChainedCall,
        MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow,
        pre_states_match_shard_selectors, validate_execution,
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
            post_states: HashMap::new(),
            shard_selectors_seen: HashSet::new(),
            public_order: Vec::new(),
            public_pre_states: HashMap::new(),
            block_validity_window,
            timestamp_validity_window,
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

            let Some(program_output) = program_outputs_iter.next() else {
                panic!("Insufficient program outputs for chained calls");
            };

            // Check that instruction data in chained call is the instruction data in program output
            assert_eq!(
                chained_call.instruction_data, program_output.instruction_data,
                "Mismatched instruction data between chained call and program output"
            );

            // Check that the callee used the requested shard selectors.
            assert!(
                // If the call is top-level, nothing to check.
                caller_data.account_id.is_none()
                    // Else, match.
                    || pre_states_match_shard_selectors(
                        &chained_call.shard_selectors,
                        &program_output.state_diffs
                    ),
                "Callee ran on shard selectors the chained call did not name"
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
        state_diffs: Vec<AccountStateDiff>,
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
            if self.shard_selectors_seen.insert(shard_selector)
                && witness.is_none()
                && let Some((program_account_id, data)) = &pre.shard
            {
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

            let post_state = &self.post_states[&account_id];
            assert_eq!(
                post_state.balance, pre.balance,
                "Inconsistent pre-state balance for account {account_id}",
            );
            if let Some((program_account_id, data)) = &pre.shard {
                assert_eq!(
                    post_state.shard(*program_account_id),
                    data,
                    "Inconsistent pre-state shard data for account {account_id}",
                );
            }

            // If an account it authorized, push it to the autorized set.
            if pre.is_authorized {
                authorized_output_accounts.push(account_id);
            }

            self.post_states
                .get_mut(&account_id)
                .expect("the account got a post state by its own check just above")
                .apply_diff(&diff)
                .expect("validate_execution checked the balance diff");
        }

        let mut authorized_accounts = caller.authorized_accounts;
        authorized_accounts.extend(authorized_output_accounts);
        authorized_accounts
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
            self.post_states.insert(
                account_id,
                AccountData {
                    balance: pre.balance,
                    ..AccountData::default()
                },
            );
            self.public_order.push(account_id);
            self.public_pre_states.insert(
                account_id,
                (
                    // Public PDAs cannot sign, so their journal authorization is false.
                    granted.is_none() && pre.is_authorized,
                    AccountData {
                        balance: pre.balance,
                        ..AccountData::default()
                    },
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
        private: Vec<(AccountId, AccountData)>,
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
        for (index, (account_id, post_state)) in private.into_iter().enumerate() {
            state.post_states.insert(account_id, post_state);
            state.witness_by_account.insert(account_id, index);
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

    const PROGRAM: AccountId = AccountId::new([0; 32]);
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
}
