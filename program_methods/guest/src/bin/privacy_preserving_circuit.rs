use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use nssa_core::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT_HASH, EncryptionScheme, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput, SharedSecretKey,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    compute_digest_for_path,
    program::{
        AccountPostState, ChainedCall, DEFAULT_PROGRAM_ID, MAX_NUMBER_CHAINED_CALLS, ProgramId,
        ProgramOutput, validate_execution,
    },
};
use risc0_zkvm::{guest::env, serde::to_vec};

/// State of the involved accounts before and after program execution.
struct ExecutionState {
    pre_states: Vec<AccountWithMetadata>,
    post_states: HashMap<AccountId, Account>,
}

impl ExecutionState {
    /// Validate program outputs and derive the overall execution state.
    pub fn derive_from_outputs(program_id: ProgramId, program_outputs: Vec<ProgramOutput>) -> Self {
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

        let mut execution_state = Self {
            pre_states: Vec::new(),
            post_states: HashMap::new(),
        };

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

            // Check that the program is well behaved.
            // See the # Programs section for the definition of the `validate_execution` method.
            let execution_valid = validate_execution(
                &program_output.pre_states,
                &program_output.post_states,
                chained_call.program_id,
            );
            assert!(execution_valid, "Bad behaved program");

            for next_call in program_output.chained_calls.iter().rev() {
                chained_calls.push_front((next_call.clone(), Some(chained_call.program_id)));
            }

            let authorized_pdas = nssa_core::program::compute_authorized_pdas(
                caller_program_id,
                &chained_call.pda_seeds,
            );
            execution_state.validate_and_sync_states(
                chained_call.program_id,
                &authorized_pdas,
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
                "Account {account_id:?} was modified but not claimed"
            );
        }

        execution_state
    }

    /// Validate program pre and post states and populate the execution state.
    fn validate_and_sync_states(
        &mut self,
        program_id: ProgramId,
        authorized_pdas: &HashSet<AccountId>,
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountPostState>,
    ) {
        for (pre, mut post) in pre_states.into_iter().zip(post_states) {
            let pre_account_id = pre.account_id;
            let post_states_entry = self.post_states.entry(pre.account_id);
            match &post_states_entry {
                Entry::Occupied(occupied) => {
                    // Ensure that new pre state is the same as known post state
                    assert_eq!(
                        occupied.get(),
                        &pre.account,
                        "Inconsistent pre state for account {pre_account_id:?}",
                    );

                    let previous_is_authorized = self
                        .pre_states
                        .iter()
                        .find(|acc| acc.account_id == pre_account_id)
                        .map_or_else(
                            || panic!(
                                "Pre state must exist in execution state for account {pre_account_id:?}",
                            ),
                            |acc| acc.is_authorized
                        );

                    let is_authorized =
                        previous_is_authorized || authorized_pdas.contains(&pre_account_id);

                    assert_eq!(
                        pre.is_authorized, is_authorized,
                        "Inconsistent authorization for account {pre_account_id:?}",
                    );
                }
                Entry::Vacant(_) => {
                    self.pre_states.push(pre);
                }
            }

            if post.requires_claim() {
                // The invoked program can only claim accounts with default program id.
                if post.account().program_owner == DEFAULT_PROGRAM_ID {
                    post.account_mut().program_owner = program_id;
                } else {
                    panic!("Cannot claim an initialized account {pre_account_id:?}");
                }
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

fn compute_circuit_output(
    execution_state: ExecutionState,
    visibility_mask: &[u8],
    private_account_nonces: &[Nonce],
    private_account_keys: &[(NullifierPublicKey, SharedSecretKey)],
    private_account_nsks: &[NullifierSecretKey],
    private_account_membership_proofs: &[Option<MembershipProof>],
) -> PrivacyPreservingCircuitOutput {
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        ciphertexts: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
    };

    let states_iter = execution_state.into_states_iter();
    assert_eq!(
        visibility_mask.len(),
        states_iter.len(),
        "Invalid visibility mask length"
    );

    let mut private_nonces_iter = private_account_nonces.iter();
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
                let Some((npk, shared_secret)) = private_keys_iter.next() else {
                    panic!("Missing private account key");
                };

                assert_eq!(
                    AccountId::from(npk),
                    pre_state.account_id,
                    "AccountId mismatch"
                );

                let new_nullifier = if account_visibility_mask == 1 {
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

                    compute_nullifier_and_set_digest(
                        membership_proof_opt.as_ref(),
                        &pre_state.account,
                        npk,
                        nsk,
                    )
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

                    let nullifier = Nullifier::for_account_initialization(npk);
                    (nullifier, DUMMY_COMMITMENT_HASH)
                };
                output.new_nullifiers.push(new_nullifier);

                // Update post-state with new nonce
                let mut post_with_updated_nonce = post_state;
                let Some(new_nonce) = private_nonces_iter.next() else {
                    panic!("Missing private account nonce");
                };
                post_with_updated_nonce.nonce = *new_nonce;

                // Compute commitment
                let commitment_post = Commitment::new(npk, &post_with_updated_nonce);

                // Encrypt and push post state
                let encrypted_account = EncryptionScheme::encrypt(
                    &post_with_updated_nonce,
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

    assert!(private_nonces_iter.next().is_none(), "Too many nonces");

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
    npk: &NullifierPublicKey,
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
            let nullifier = Nullifier::for_account_initialization(npk);
            (nullifier, DUMMY_COMMITMENT_HASH)
        },
        |membership_proof| {
            // Compute commitment set digest associated with provided auth path
            let commitment_pre = Commitment::new(npk, pre_account);
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
        private_account_nonces,
        private_account_keys,
        private_account_nsks,
        private_account_membership_proofs,
        program_id,
    } = env::read();

    let execution_state = ExecutionState::derive_from_outputs(program_id, program_outputs);

    let output = compute_circuit_output(
        execution_state,
        &visibility_mask,
        &private_account_nonces,
        &private_account_keys,
        &private_account_nsks,
        &private_account_membership_proofs,
    );

    env::commit(&output);
}
