use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    Identifier, InputAccountIdentity, NullifierPublicKey, PrivateWitness, WitnessKind,
    account::{AccountId, Input, Slot},
    encryption::ViewingPublicKey,
    program::{
        BlockValidityWindow, CallerData, ChainedCall, MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramId,
        ProgramOutput, TimestampValidityWindow, validate_execution,
    },
};
use risc0_zkvm::guest::env;

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    pre_states: Vec<Input>,
    /// Keyed by the position, not the account: a slot's effect is its own.
    post_states: HashMap<(AccountId, AccountId), Slot>,
    /// The positions already written to `pre_states`, keyed exactly as the public path keys
    /// `positions_seen`. A first sighting is anchored to chain state and journalled; a later one
    /// is anchored to what an earlier frame wrote and must not be journalled again. Address-only
    /// positions leave no post behind, so post-presence cannot answer this for them.
    journalled: HashSet<(AccountId, Option<AccountId>)>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Accounts declared authorized at their first sight, anywhere in the call tree.
    /// Authorization is monotone: they remain authorized throughout all calls.
    globally_authorized: HashSet<AccountId>,
    /// The private-PDA keys supplied at each account's first sight, so a caller's seeds can be
    /// re-matched against the private derivation on later calls.
    private_pda_keys: HashMap<AccountId, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    /// Across the whole transaction each `(program, seed)` resolves to at most one account, so
    /// one delegated seed cannot authorize several members of the same PDA family.
    pda_family_binding: HashMap<(ProgramId, PdaSeed), AccountId>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(
        account_identities: &[InputAccountIdentity],
        program_id: ProgramId,
        program_outputs: Vec<ProgramOutput>,
    ) -> Self {
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
            journalled: HashSet::new(),
            block_validity_window,
            timestamp_validity_window,
            globally_authorized: HashSet::new(),
            private_pda_keys: HashMap::new(),
            pda_family_binding: HashMap::new(),
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

            let authorized_accounts = execution_state.validate_and_sync_states(
                account_identities,
                caller_data,
                &chained_call.pda_seeds,
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

        execution_state
    }

    /// Validate program pre and post states and populate the execution state.
    ///
    /// Return the set of authorized accounts as the result of the processed
    /// call.
    fn validate_and_sync_states(
        &mut self,
        account_identities: &[InputAccountIdentity],
        caller: CallerData,
        caller_pda_seeds: &[PdaSeed],
        output_pre_states: Vec<Input>,
        output_post_states: Vec<Option<Slot>>,
    ) -> HashSet<AccountId> {
        let mut authorized_output_accounts = Vec::new();
        // Two passes, mirroring the public path: every pre state is checked against the
        // state as of the PREVIOUS frame before any of this frame's posts land. Every
        // position is visited — `validate_execution` has already rejected two positions
        // naming the same one, and one account may legitimately hold two namespaces.
        for pre in &output_pre_states {
            // A position is journalled once, at its first sight, and is anchored there to chain
            // state. Later sightings are anchored to what an earlier frame in this tree wrote.
            let position = (
                pre.account_id,
                pre.slot.as_ref().map(|(program, _)| *program),
            );
            if self.journalled.insert(position) {
                self.journal_first_sight(account_identities, &caller, caller_pda_seeds, pre);
            } else {
                self.check_known_position(&caller, caller_pda_seeds, pre);
            }

            // If an account it authorized, push it to the autorized set.
            if pre.is_authorized {
                authorized_output_accounts.push(pre.account_id);
            }
        }

        for (pre, post) in output_pre_states.into_iter().zip(output_post_states) {
            if let (Some((program, _)), Some(post_slot)) = (pre.slot, post) {
                self.post_states
                    .insert((pre.account_id, program), post_slot);
            }
        }

        let mut authorized_accounts = caller.authorized_accounts;
        authorized_accounts.extend(authorized_output_accounts);
        authorized_accounts
    }

    /// A position seen for the first time. Nothing in this tree has written it yet, so it is
    /// journalled: the verifier is what anchors the entry, against chain state for a public
    /// account and against the committed witness for a private one. A private PDA's npk is
    /// bound to its address here, once, because the witness is the only link between them.
    fn journal_first_sight(
        &mut self,
        account_identities: &[InputAccountIdentity],
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        pre: &Input,
    ) {
        let pre_account_id = pre.account_id;
        let pre_state_position = self.pre_states.len();
        let mut journal_pre = pre.clone();
        match account_identities.get(pre_state_position) {
            Some(InputAccountIdentity::Private(PrivateWitness {
                vpk,
                identifier,
                kind:
                    WitnessKind::Pda {
                        binding: (authority_program_id, seed),
                    },
                nullifier,
                ..
            })) => {
                let keys = (nullifier.npk(), vpk.clone(), *identifier);
                assert_eq!(
                    pre_account_id,
                    AccountId::for_private_pda(
                        authority_program_id,
                        seed,
                        &keys.0,
                        &keys.1,
                        keys.2
                    ),
                    "Private PDA at position {pre_state_position} does not match its witness binding"
                );
                let granted = seed_granted(caller, caller_pda_seeds, pre_account_id, Some(&keys));
                if let Some((granting_program, granting_seed)) = granted {
                    assert_family_binding(
                        &mut self.pda_family_binding,
                        granting_program,
                        granting_seed,
                        pre_account_id,
                    );
                }
                assert_eq!(
                    pre.is_authorized,
                    granted.is_some(),
                    "Inconsistent authorization for private PDA {pre_account_id}"
                );
                self.private_pda_keys.insert(pre_account_id, keys);
            }
            _ => match seed_granted(caller, caller_pda_seeds, pre_account_id, None) {
                Some((program_id, seed)) => {
                    assert!(
                        pre.is_authorized,
                        "Caller-seeded public PDA must be declared authorized at first sight: {pre_account_id}"
                    );
                    assert_family_binding(
                        &mut self.pda_family_binding,
                        program_id,
                        seed,
                        pre_account_id,
                    );
                    // The verifier re-derives a public account's authorization from the signer
                    // set, where a keyless PDA can never appear, so the journal must report the
                    // credential it has, not the grant.
                    journal_pre.is_authorized = false;
                }
                None => {
                    if pre.is_authorized {
                        self.globally_authorized.insert(pre_account_id);
                    }
                }
            },
        }
        self.pre_states.push(journal_pre);
    }

    /// A position already journalled by an earlier frame. It is anchored to what that frame
    /// left behind rather than to chain state, so both its slot and its authorization are
    /// checked here against what this tree already established.
    fn check_known_position(
        &mut self,
        caller: &CallerData,
        caller_pda_seeds: &[PdaSeed],
        pre: &Input,
    ) {
        let pre_account_id = pre.account_id;
        if let Some((program, slot)) = &pre.slot {
            let known_post = self
                .post_states
                .get(&(pre_account_id, *program))
                .expect("a journalled slot position has left a post behind");
            assert_eq!(
                known_post, slot,
                "Inconsistent pre state for account {pre_account_id}",
            );
        }

        let granted = seed_granted(
            caller,
            caller_pda_seeds,
            pre_account_id,
            self.private_pda_keys.get(&pre_account_id),
        );
        if let Some((program_id, seed)) = granted {
            assert_family_binding(
                &mut self.pda_family_binding,
                program_id,
                seed,
                pre_account_id,
            );
        }
        let is_authorized = granted.is_some()
            || self.globally_authorized.contains(&pre_account_id)
            || caller.authorized_accounts.contains(&pre_account_id);
        assert_eq!(
            pre.is_authorized, is_authorized,
            "Inconsistent authorization for account {pre_account_id}",
        );
    }

    /// The state a completed call tree leaves behind, built directly. Lets the output stage be
    /// tested against the host without a guest ELF to replay the tree through.
    #[cfg(test)]
    pub(crate) fn from_positions(positions: Vec<(Input, Option<Slot>)>) -> Self {
        let mut pre_states = Vec::new();
        let mut post_states = HashMap::new();
        let mut journalled = HashSet::new();
        for (pre, post) in positions {
            journalled.insert((
                pre.account_id,
                pre.slot.as_ref().map(|(program, _)| *program),
            ));
            if let (Some((program, _)), Some(post)) = (&pre.slot, post) {
                post_states.insert((pre.account_id, *program), post);
            }
            pre_states.push(pre);
        }
        Self {
            pre_states,
            post_states,
            journalled,
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            globally_authorized: HashSet::new(),
            private_pda_keys: HashMap::new(),
            pda_family_binding: HashMap::new(),
        }
    }

    /// Consume self and yield the validity windows and an iterator over pre and post states of
    /// each account involved in the execution. Returning everything together keeps the
    /// fields module-private rather than forcing them visible to downstream consumers.
    pub fn into_parts(
        mut self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        impl ExactSizeIterator<Item = (Input, Option<Slot>)>,
    ) {
        let block_validity_window = self.block_validity_window;
        let timestamp_validity_window = self.timestamp_validity_window;
        let states_iter = self.pre_states.into_iter().map(move |pre| {
            let post = pre.slot.as_ref().map(|(program, _)| {
                self.post_states
                    .remove(&(pre.account_id, *program))
                    .expect("Named slot from pre states should exist in state diff")
            });
            (pre, post)
        });
        (
            block_validity_window,
            timestamp_validity_window,
            states_iter,
        )
    }
}

/// A caller may delegate its own PDAs to this callee by seed. That is the only way a keyless
/// address can be authorized, in either form: `keys` selects the private derivation, its absence
/// the public one.
fn seed_granted(
    caller: &CallerData,
    caller_pda_seeds: &[PdaSeed],
    account_id: AccountId,
    keys: Option<&(NullifierPublicKey, ViewingPublicKey, Identifier)>,
) -> Option<(ProgramId, PdaSeed)> {
    let caller_program_id = caller.program_id?;
    caller_pda_seeds.iter().find_map(|seed| {
        let derived = match keys {
            Some((npk, vpk, identifier)) => {
                AccountId::for_private_pda(&caller_program_id, seed, npk, vpk, *identifier)
            }
            None => AccountId::for_public_pda(&caller_program_id, seed),
        };
        (derived == account_id).then_some((caller_program_id, *seed))
    })
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
