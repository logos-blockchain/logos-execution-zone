use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use nssa_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, Timestamp,
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        ChainedCall, Claim, DEFAULT_PROGRAM_ID, ProgramId, ProgramOutput,
        compute_public_authorized_pdas, validate_execution,
    },
};

use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, NssaError},
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction, circuit::Proof, message::Message,
    },
    program::Program,
    program_deployment_transaction::ProgramDeploymentTransaction,
    public_transaction::PublicTransaction,
    state::MAX_NUMBER_CHAINED_CALLS,
};

pub struct StateDiff {
    pub signer_account_ids: Vec<AccountId>,
    pub public_diff: HashMap<AccountId, Account>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<Nullifier>,
    pub program: Option<Program>,
}

/// The validated output of executing or verifying a transaction, ready to be applied to the state.
///
/// Can only be constructed by the transaction validation functions inside this crate, ensuring the
/// diff has been checked before any state mutation occurs.
pub struct ValidatedStateDiff(StateDiff);

impl ValidatedStateDiff {
    pub fn from_public_transaction(
        tx: &PublicTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, NssaError> {
        let validator = PublicTransactionValidator::new(tx, state, block_id, timestamp);
        let state_diff = crate::public_transaction::execute(validator, tx, state)?;

        Ok(Self(StateDiff {
            signer_account_ids: tx.signer_account_ids(),
            public_diff: state_diff,
            new_commitments: vec![],
            new_nullifiers: vec![],
            program: None,
        }))
    }

    pub fn from_privacy_preserving_transaction(
        tx: &PrivacyPreservingTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, NssaError> {
        let message = &tx.message;
        let witness_set = &tx.witness_set;

        // 1. Commitments or nullifiers are non empty
        ensure!(
            !message.new_commitments.is_empty() || !message.new_nullifiers.is_empty(),
            NssaError::InvalidInput(
                "Empty commitments and empty nullifiers found in message".into(),
            )
        );

        // 2. Check there are no duplicate account_ids in the public_account_ids list.
        ensure!(
            n_unique(&message.public_account_ids) == message.public_account_ids.len(),
            NssaError::InvalidInput("Duplicate account_ids found in message".into())
        );

        // Check there are no duplicate nullifiers in the new_nullifiers list
        ensure!(
            n_unique(&message.new_nullifiers) == message.new_nullifiers.len(),
            NssaError::InvalidInput("Duplicate nullifiers found in message".into())
        );

        // Check there are no duplicate commitments in the new_commitments list
        ensure!(
            n_unique(&message.new_commitments) == message.new_commitments.len(),
            NssaError::InvalidInput("Duplicate commitments found in message".into())
        );

        // 3. Nonce checks and Valid signatures
        // Check exactly one nonce is provided for each signature
        ensure!(
            message.nonces.len() == witness_set.signatures_and_public_keys.len(),
            NssaError::InvalidInput(
                "Mismatch between number of nonces and signatures/public keys".into(),
            )
        );

        // Check the signatures are valid
        ensure!(
            witness_set.signatures_are_valid_for(message),
            NssaError::InvalidInput("Invalid signature for given message and public key".into())
        );

        let signer_account_ids = tx.signer_account_ids();
        // Check nonces corresponds to the current nonces on the public state.
        for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
            let current_nonce = state.get_account_by_id(*account_id).nonce;
            ensure!(
                current_nonce == *nonce,
                NssaError::InvalidInput("Nonce mismatch".into())
            );
        }

        // Verify validity window
        ensure!(
            message.block_validity_window.is_valid_for(block_id)
                && message.timestamp_validity_window.is_valid_for(timestamp),
            NssaError::OutOfValidityWindow
        );

        // Build pre_states for proof verification
        let public_pre_states: Vec<_> = message
            .public_account_ids
            .iter()
            .map(|account_id| {
                AccountWithMetadata::new(
                    state.get_account_by_id(*account_id),
                    signer_account_ids.contains(account_id),
                    *account_id,
                )
            })
            .collect();

        // 4. Proof verification
        check_privacy_preserving_circuit_proof_is_valid(
            &witness_set.proof,
            &public_pre_states,
            message,
        )?;

        // 5. Commitment freshness
        state.check_commitments_are_new(&message.new_commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&message.new_nullifiers)?;

        let public_diff = message
            .public_account_ids
            .iter()
            .copied()
            .zip(message.public_post_states.clone())
            .collect();
        let new_nullifiers = message
            .new_nullifiers
            .iter()
            .copied()
            .map(|(nullifier, _)| nullifier)
            .collect();

        Ok(Self(StateDiff {
            signer_account_ids,
            public_diff,
            new_commitments: message.new_commitments.clone(),
            new_nullifiers,
            program: None,
        }))
    }

    pub fn from_program_deployment_transaction(
        tx: &ProgramDeploymentTransaction,
        state: &V03State,
    ) -> Result<Self, NssaError> {
        // TODO: remove clone
        let program = Program::new(tx.message.bytecode.clone())?;
        if state.programs().contains_key(&program.id()) {
            return Err(NssaError::ProgramAlreadyExists);
        }
        Ok(Self(StateDiff {
            signer_account_ids: vec![],
            public_diff: HashMap::new(),
            new_commitments: vec![],
            new_nullifiers: vec![],
            program: Some(program),
        }))
    }

    pub fn from_public_genesis_transaction(
        tx: &PublicTransaction,
        state: &V03State,
    ) -> Result<Self, NssaError> {
        let validator = GenesisPublicTransactionValidator;
        let state_diff = crate::public_transaction::execute(validator, tx, state)?;

        Ok(Self(StateDiff {
            signer_account_ids: tx.signer_account_ids(),
            public_diff: state_diff,
            new_commitments: vec![],
            new_nullifiers: vec![],
            program: None,
        }))
    }

    /// Returns the public account changes produced by this transaction.
    ///
    /// Used by callers (e.g. the sequencer) to inspect the diff before committing it, for example
    /// to enforce that system accounts are not modified by user transactions.
    #[must_use]
    pub fn public_diff(&self) -> HashMap<AccountId, Account> {
        self.0.public_diff.clone()
    }

    pub(crate) fn into_state_diff(self) -> StateDiff {
        self.0
    }
}

pub struct PublicTransactionValidator<'tx, 'state> {
    tx: &'tx PublicTransaction,
    state: &'state V03State,
    block_id: BlockId,
    timestamp: Timestamp,
    chain_calls_counter: usize,
}

impl<'tx, 'state> PublicTransactionValidator<'tx, 'state> {
    pub const fn new(
        tx: &'tx PublicTransaction,
        state: &'state V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            tx,
            state,
            block_id,
            timestamp,
            chain_calls_counter: 0,
        }
    }
}

impl crate::public_transaction::Validator for PublicTransactionValidator<'_, '_> {
    fn validate_pre_execution(&mut self) -> Result<(), NssaError> {
        let message = self.tx.message();
        let witness_set = self.tx.witness_set();

        // All account_ids must be different
        ensure!(
            message.account_ids.iter().collect::<HashSet<_>>().len() == message.account_ids.len(),
            NssaError::InvalidInput("Duplicate account_ids found in message".into(),)
        );

        // Check exactly one nonce is provided for each signature
        ensure!(
            message.nonces.len() == witness_set.signatures_and_public_keys.len(),
            NssaError::InvalidInput(
                "Mismatch between number of nonces and signatures/public keys".into(),
            )
        );

        // Check the signatures are valid
        ensure!(
            witness_set.is_valid_for(message),
            NssaError::InvalidInput("Invalid signature for given message and public key".into())
        );

        let signer_account_ids = self.tx.signer_account_ids();
        // Check nonces corresponds to the current nonces on the public state.
        for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
            let current_nonce = self.state.get_account_by_id(*account_id).nonce;
            ensure!(
                current_nonce == *nonce,
                NssaError::InvalidInput("Nonce mismatch".into())
            );
        }

        Ok(())
    }

    fn on_chained_call(&mut self) -> Result<(), NssaError> {
        self.chain_calls_counter = self
            .chain_calls_counter
            .checked_add(1)
            .ok_or(NssaError::MaxChainedCallsDepthExceeded)?;
        ensure!(
            self.chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
            NssaError::MaxChainedCallsDepthExceeded
        );
        Ok(())
    }

    fn validate_output(
        &mut self,
        state_diff: &HashMap<AccountId, Account>,
        caller_program_id: Option<ProgramId>,
        chained_call: &ChainedCall,
        program_output: &ProgramOutput,
    ) -> Result<(), NssaError> {
        let authorized_pdas =
            compute_public_authorized_pdas(caller_program_id, &chained_call.pda_seeds);

        let is_authorized = |account_id: &AccountId| {
            self.tx.signer_account_ids().contains(account_id)
                || authorized_pdas.contains(account_id)
        };

        for pre in &program_output.pre_states {
            let account_id = pre.account_id;
            // Check that the program output pre_states coincide with the values in the public
            // state or with any modifications to those values during the chain of calls.
            let expected_pre = state_diff
                .get(&account_id)
                .cloned()
                .unwrap_or_else(|| self.state.get_account_by_id(account_id));
            ensure!(
                pre.account == expected_pre,
                InvalidProgramBehaviorError::InconsistentAccountPreState {
                    account_id,
                    expected: Box::new(expected_pre),
                    actual: Box::new(pre.account.clone())
                }
            );

            // Check that authorization flags are consistent with the provided ones or
            // authorized by program through the PDA mechanism
            let expected_is_authorized = is_authorized(&account_id);
            ensure!(
                pre.is_authorized == expected_is_authorized,
                InvalidProgramBehaviorError::InconsistentAccountAuthorization {
                    account_id,
                    expected_authorization: expected_is_authorized,
                    actual_authorization: pre.is_authorized
                }
            );
        }

        // Verify that the program output's self_program_id matches the expected program ID.
        ensure!(
            program_output.self_program_id == chained_call.program_id,
            InvalidProgramBehaviorError::MismatchedProgramId {
                expected: chained_call.program_id,
                actual: program_output.self_program_id
            }
        );

        // Verify that the program output's caller_program_id matches the actual caller.
        ensure!(
            program_output.caller_program_id == caller_program_id,
            InvalidProgramBehaviorError::MismatchedCallerProgramId {
                expected: caller_program_id,
                actual: program_output.caller_program_id,
            }
        );

        // Verify execution corresponds to a well-behaved program.
        // See the # Programs section for the definition of the `validate_execution` method.
        validate_execution(
            &program_output.pre_states,
            &program_output.post_states,
            chained_call.program_id,
        )
        .map_err(InvalidProgramBehaviorError::ExecutionValidationFailed)?;

        // Verify validity window
        ensure!(
            program_output
                .block_validity_window
                .is_valid_for(self.block_id)
                && program_output
                    .timestamp_validity_window
                    .is_valid_for(self.timestamp),
            NssaError::OutOfValidityWindow
        );

        for (i, post) in program_output.post_states.iter().enumerate() {
            let Some(claim) = post.required_claim() else {
                continue;
            };
            let account_id = program_output.pre_states[i].account_id;

            // The invoked program can only claim accounts with default program id.
            ensure!(
                post.account().program_owner == DEFAULT_PROGRAM_ID,
                InvalidProgramBehaviorError::ClaimedNonDefaultAccount { account_id }
            );

            match claim {
                Claim::Authorized => {
                    // The program can only claim accounts that were authorized by the signer.
                    ensure!(
                        is_authorized(&account_id),
                        InvalidProgramBehaviorError::ClaimedUnauthorizedAccount { account_id }
                    );
                }
                Claim::Pda(seed) => {
                    // The program can only claim accounts that correspond to the PDAs it is
                    // authorized to claim.
                    let pda = AccountId::for_public_pda(&chained_call.program_id, &seed);
                    ensure!(
                        account_id == pda,
                        InvalidProgramBehaviorError::MismatchedPdaClaim {
                            expected: pda,
                            actual: account_id
                        }
                    );
                }
            }
        }

        Ok(())
    }

    fn validate_post_execution(
        &mut self,
        state_diff: &HashMap<AccountId, Account>,
    ) -> Result<(), NssaError> {
        // Check that all modified uninitialized accounts where claimed
        for (account_id, post) in state_diff.iter().filter_map(|(account_id, post)| {
            let pre = self.state.get_account_by_id(*account_id);
            if pre.program_owner != DEFAULT_PROGRAM_ID {
                return None;
            }
            if pre == *post {
                return None;
            }
            Some((*account_id, post))
        }) {
            ensure!(
                post.program_owner != DEFAULT_PROGRAM_ID,
                InvalidProgramBehaviorError::DefaultAccountModifiedWithoutClaim { account_id }
            );
        }

        Ok(())
    }
}

pub struct GenesisPublicTransactionValidator;

impl crate::public_transaction::Validator for GenesisPublicTransactionValidator {
    fn validate_pre_execution(&mut self) -> Result<(), NssaError> {
        Ok(())
    }

    fn on_chained_call(&mut self) -> Result<(), NssaError> {
        Ok(())
    }

    fn validate_output(
        &mut self,
        _state_diff: &HashMap<AccountId, Account>,
        _caller_program_id: Option<ProgramId>,
        _chained_call: &ChainedCall,
        _program_output: &ProgramOutput,
    ) -> Result<(), NssaError> {
        Ok(())
    }

    fn validate_post_execution(
        &mut self,
        _state_diff: &HashMap<AccountId, Account>,
    ) -> Result<(), NssaError> {
        Ok(())
    }
}

fn check_privacy_preserving_circuit_proof_is_valid(
    proof: &Proof,
    public_pre_states: &[AccountWithMetadata],
    message: &Message,
) -> Result<(), NssaError> {
    let output = PrivacyPreservingCircuitOutput {
        public_pre_states: public_pre_states.to_vec(),
        public_post_states: message.public_post_states.clone(),
        ciphertexts: message
            .encrypted_private_post_states
            .iter()
            .cloned()
            .map(|value| value.ciphertext)
            .collect(),
        new_commitments: message.new_commitments.clone(),
        new_nullifiers: message.new_nullifiers.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
    };
    proof
        .is_valid_for(&output)
        .then_some(())
        .ok_or(NssaError::InvalidPrivacyPreservingProof)
}

fn n_unique<T: Eq + Hash>(data: &[T]) -> usize {
    let set: HashSet<&T> = data.iter().collect();
    set.len()
}
