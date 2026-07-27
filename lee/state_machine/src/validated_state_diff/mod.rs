use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use lee_core::{
    Authorization, Backend, BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput,
    Resolved, Timestamp, ValidationError,
    account::{Account, AccountId, AccountWithMetadata},
    program::{ChainedCall, PdaSeed, ProgramId, ProgramOutput},
    validate_state_diff,
};

use crate::{
    V03State, ensure,
    error::LeeError,
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction, circuit::Proof, message::Message,
    },
    program::Program,
    program_deployment_transaction::ProgramDeploymentTransaction,
    public_transaction::PublicTransaction,
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
    ) -> Result<Self, LeeError> {
        let signer_account_ids = authenticate_public_transaction_signers(tx, state)?;
        let message = tx.message();

        ensure!(
            !message.account_ids.is_empty(),
            LeeError::InvalidInput("Public transaction must have at least one account".into())
        );

        // All account_ids must be different
        ensure!(
            message.account_ids.iter().collect::<HashSet<_>>().len() == message.account_ids.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into(),)
        );

        // Build pre_states for execution
        let input_pre_states: Vec<_> = message
            .account_ids
            .iter()
            .map(|account_id| {
                AccountWithMetadata::new(
                    state.get_account_by_id(*account_id),
                    signer_account_ids.contains(account_id),
                    *account_id,
                )
            })
            .collect();

        let initial_call = ChainedCall {
            program_id: message.program_id,
            instruction_data: message.instruction_data.clone(),
            pre_states: input_pre_states,
            pda_seeds: vec![],
        };

        let mut env = PublicEnv {
            state,
            signers: signer_account_ids.iter().copied().collect(),
        };
        let threaded = validate_state_diff(&mut env, initial_call)?;

        ensure!(
            threaded.block_validity_window.is_valid_for(block_id)
                && threaded.timestamp_validity_window.is_valid_for(timestamp),
            LeeError::OutOfValidityWindow
        );

        let public_diff = threaded
            .accounts
            .into_iter()
            .map(|(pre, post)| (pre.account_id, post))
            .collect();

        Ok(Self(StateDiff {
            signer_account_ids,
            public_diff,
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
    ) -> Result<Self, LeeError> {
        let message = &tx.message;
        let witness_set = &tx.witness_set;

        // 1. Commitments or nullifiers are non empty
        ensure!(
            !message.new_commitments.is_empty() || !message.new_nullifiers.is_empty(),
            LeeError::InvalidInput(
                "Empty commitments and empty nullifiers found in message".into(),
            )
        );

        // 2. Check there are no duplicate account_ids in the public_account_ids list.
        ensure!(
            n_unique(&message.public_account_ids) == message.public_account_ids.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into())
        );

        // Check there are no duplicate nullifiers in the new_nullifiers list
        ensure!(
            n_unique(
                &message
                    .new_nullifiers
                    .iter()
                    .map(|(n, _)| n)
                    .collect::<Vec<_>>()
            ) == message.new_nullifiers.len(),
            LeeError::InvalidInput("Duplicate nullifiers found in message".into())
        );

        // Check there are no duplicate commitments in the new_commitments list
        ensure!(
            n_unique(&message.new_commitments) == message.new_commitments.len(),
            LeeError::InvalidInput("Duplicate commitments found in message".into())
        );

        // 3. Nonce checks and Valid signatures
        // Check exactly one nonce is provided for each signature
        ensure!(
            message.nonces.len() == witness_set.signatures_and_public_keys.len(),
            LeeError::InvalidInput(
                "Mismatch between number of nonces and signatures/public keys".into(),
            )
        );

        // Check the signatures are valid
        ensure!(
            witness_set.signatures_are_valid_for(message),
            LeeError::InvalidInput("Invalid signature for given message and public key".into())
        );

        let signer_account_ids = tx.signer_account_ids();
        // Check nonces corresponds to the current nonces on the public state.
        for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
            let current_nonce = state.get_account_by_id(*account_id).nonce;
            ensure!(
                current_nonce == *nonce,
                LeeError::InvalidInput("Nonce mismatch".into())
            );
        }

        // Verify validity window
        ensure!(
            message.block_validity_window.is_valid_for(block_id)
                && message.timestamp_validity_window.is_valid_for(timestamp),
            LeeError::OutOfValidityWindow
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
    ) -> Result<Self, LeeError> {
        // TODO: remove clone
        let program = Program::new(tx.message.bytecode.clone().into())?;
        if state.programs().contains_key(&program.id()) {
            return Err(LeeError::ProgramAlreadyExists);
        }
        Ok(Self(StateDiff {
            signer_account_ids: vec![],
            public_diff: HashMap::new(),
            new_commitments: vec![],
            new_nullifiers: vec![],
            program: Some(program),
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

struct PublicEnv<'state> {
    state: &'state V03State,
    signers: HashSet<AccountId>,
}

impl Backend for PublicEnv<'_> {
    type Error = LeeError;

    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        caller: Option<ProgramId>,
    ) -> Result<ProgramOutput, LeeError> {
        let Some(program) = self.state.programs().get(&call.program_id) else {
            return Err(LeeError::InvalidInput("Unknown program".into()));
        };
        program.execute(caller, &call.pre_states, &call.instruction_data)
    }

    fn resolve_pre_state(
        &mut self,
        pre: &AccountWithMetadata,
    ) -> Result<Resolved, ValidationError> {
        let authorization = if self.signers.contains(&pre.account_id) {
            Authorization::Holder
        } else {
            Authorization::None
        };
        Ok(Resolved {
            account: self.state.get_account_by_id(pre.account_id),
            authorization,
        })
    }

    fn try_bind_pda(
        &mut self,
        program_id: ProgramId,
        seed: PdaSeed,
        account_id: AccountId,
    ) -> Result<bool, ValidationError> {
        Ok(account_id.matches_public_pda(&program_id, &seed))
    }

    fn witness_derives_account_id(&self, _pre: &AccountWithMetadata) -> bool {
        false
    }

    fn finalize(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl From<ValidationError> for LeeError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::ProgramBehavior(error) => Self::InvalidProgramBehavior(error),
            ValidationError::MaxChainedCallsDepthExceeded => Self::MaxChainedCallsDepthExceeded,
            ValidationError::OutOfValidityWindow => Self::OutOfValidityWindow,
        }
    }
}

fn authenticate_public_transaction_signers(
    tx: &PublicTransaction,
    state: &V03State,
) -> Result<Vec<AccountId>, LeeError> {
    let message = tx.message();
    let witness_set = tx.witness_set();

    ensure!(
        message.nonces.len() == witness_set.signatures_and_public_keys.len(),
        LeeError::InvalidInput(
            "Mismatch between number of nonces and signatures/public keys".into(),
        )
    );

    ensure!(
        witness_set.is_valid_for(message),
        LeeError::InvalidInput("Invalid signature for given message and public key".into())
    );

    let signer_account_ids = tx.signer_account_ids();
    for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
        let current_nonce = state.get_account_by_id(*account_id).nonce;
        ensure!(
            current_nonce == *nonce,
            LeeError::InvalidInput("Nonce mismatch".into())
        );
    }

    Ok(signer_account_ids)
}

fn check_privacy_preserving_circuit_proof_is_valid(
    proof: &Proof,
    public_pre_states: &[AccountWithMetadata],
    message: &Message,
) -> Result<(), LeeError> {
    let output = PrivacyPreservingCircuitOutput {
        public_pre_states: public_pre_states.to_vec(),
        public_post_states: message.public_post_states.clone(),
        encrypted_private_post_states: message.encrypted_private_post_states.clone(),
        new_commitments: message.new_commitments.clone(),
        new_nullifiers: message.new_nullifiers.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
    };
    proof
        .is_valid_for(&output)
        .then_some(())
        .ok_or(LeeError::InvalidPrivacyPreservingProof)
}

fn n_unique<T: Eq + Hash>(data: &[T]) -> usize {
    let set: HashSet<&T> = data.iter().collect();
    set.len()
}

#[cfg(test)]
mod tests;
