use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
};

use lee_core::{
    InputAccountIdentity, PrivateWitness, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        BlockValidityWindow, CallerData, ChainedCall, MAX_NUMBER_CHAINED_CALLS, ProgramId,
        ProgramOutput, TimestampValidityWindow, validate_execution,
    },
};
use risc0_zkvm::guest::env;

/// State of the involved accounts before and after program execution.
pub struct ExecutionState {
    pre_states: Vec<AccountWithMetadata>,
    post_states: HashMap<AccountId, Account>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    /// Accounts declared authorized at their first sight, anywhere in the call tree.
    /// Authorization is monotone: they remain authorized throughout all calls.
    globally_authorized: HashSet<AccountId>,
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
            block_validity_window,
            timestamp_validity_window,
            globally_authorized: HashSet::new(),
        };

        let Some(first_output) = program_outputs.first() else {
            panic!("No program outputs provided");
        };

        let initial_call = ChainedCall {
            program_id,
            instruction_data: first_output.instruction_data.clone(),
            pre_states: first_output.pre_states.clone(),
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
        output_pre_states: Vec<AccountWithMetadata>,
        output_post_states: Vec<Account>,
    ) -> HashSet<AccountId> {
        let mut authorized_output_accounts = Vec::new();
        // Two passes, mirroring the public path: every pre state is checked against the
        // state as of the PREVIOUS frame before any of this frame's posts land. A repeated
        // position within the frame is skipped — `validate_execution` has already pinned
        // its pre and post as identical to the first occurrence's.
        let mut seen_in_frame = HashSet::new();
        for pre in &output_pre_states {
            let pre_account_id = pre.account_id;
            let pre_is_authorized = pre.is_authorized;
            if !seen_in_frame.insert(pre_account_id) {
                continue;
            }
            if let Some(known_post) = self.post_states.get(&pre_account_id) {
                // Ensure that new pre state is the same as known post state
                assert_eq!(
                    known_post, &pre.account,
                    "Inconsistent pre state for account {pre_account_id}",
                );

                let is_authorized = self.globally_authorized.contains(&pre_account_id)
                    || caller.authorized_accounts.contains(&pre_account_id);
                assert_eq!(
                    pre_is_authorized, is_authorized,
                    "Inconsistent authorization for account {pre_account_id}",
                );
            } else {
                // Pre state for the initial call
                let pre_state_position = self.pre_states.len();
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
                        // The witness is the only link between the supplied npk and the
                        // address, so it is proven here, once, at first sight.
                        assert_eq!(
                            pre_account_id,
                            AccountId::for_private_pda(
                                authority_program_id,
                                seed,
                                &nullifier.npk(),
                                vpk,
                                *identifier,
                            ),
                            "Private PDA at position {pre_state_position} does not match its witness binding"
                        );
                        // A PDA is rooted in a derivation, not in a credential: nothing
                        // could discharge such a declaration, here or at the verifier.
                        assert!(
                            !pre_is_authorized,
                            "Private PDA {pre_account_id} cannot be authorized"
                        );
                    }
                    _ => {
                        if pre_is_authorized {
                            self.globally_authorized.insert(pre_account_id);
                        }
                    }
                }
                self.pre_states.push(pre.clone());
            }

            // If an account it authorized, push it to the autorized set.
            if pre_is_authorized {
                authorized_output_accounts.push(pre_account_id);
            }
        }

        for (pre, post) in output_pre_states.into_iter().zip(output_post_states) {
            self.post_states.insert(pre.account_id, post);
        }

        let mut authorized_accounts = caller.authorized_accounts;
        authorized_accounts.extend(authorized_output_accounts);
        authorized_accounts
    }

    /// Consume self and yield the validity windows and an iterator over pre and post states of
    /// each account involved in the execution. Returning everything together keeps the
    /// fields module-private rather than forcing them visible to downstream consumers.
    pub fn into_parts(
        mut self,
    ) -> (
        BlockValidityWindow,
        TimestampValidityWindow,
        impl ExactSizeIterator<Item = (AccountWithMetadata, Account)>,
    ) {
        let block_validity_window = self.block_validity_window;
        let timestamp_validity_window = self.timestamp_validity_window;
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
            states_iter,
        )
    }
}
