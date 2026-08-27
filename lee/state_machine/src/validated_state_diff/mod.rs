use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, PublicAction, Timestamp,
    account::{Account, AccountId, AccountWithMetadata, Nonce, apply_balance_diff},
    program::{
        CallerData, ChainedCall, Claim, DEFAULT_PROGRAM_OWNER, compute_public_authorized_pdas,
        validate_execution,
    },
};
use log::debug;

use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
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
/// It can only be constructed by the transaction validation functions inside this crate, ensuring
/// the diff has been checked before any state mutation occurs. Under the `test-utils` feature the
/// [`crate::test_utils`] module additionally exposes a hand-rolled constructor for unit-testing
/// downstream validation logic; that feature must never be enabled in a production build.
pub struct ValidatedStateDiff(StateDiff);

#[cfg(feature = "test-utils")]
impl ValidatedStateDiff {
    /// Test-only constructor that wraps an already-built [`StateDiff`] **without validating it**.
    ///
    /// Kept in this module so the wrapped field can stay private: in a normal build (feature off)
    /// the only ways to obtain a `ValidatedStateDiff` remain the `from_*_transaction` validators.
    #[must_use]
    pub const fn new_unchecked(state_diff: StateDiff) -> Self {
        Self(state_diff)
    }
}

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
            n_unique(&message.account_ids) == message.account_ids.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into(),)
        );

        let mut state_diff: HashMap<AccountId, Account> = HashMap::new();

        let initial_call = ChainedCall {
            program_id: message.program_id,
            instruction_data: message.instruction_data.clone(),
            accounts: message.account_ids.clone(),
            pda_seeds: vec![],
        };

        let initial_caller_data = CallerData {
            program_id: None,
            authorized_accounts: signer_account_ids.iter().copied().collect(),
        };

        let mut chained_calls =
            VecDeque::<(ChainedCall, CallerData)>::from_iter([(initial_call, initial_caller_data)]);
        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
            ensure!(
                chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
                LeeError::MaxChainedCallsDepthExceeded
            );

            let Some(program_account) = state.get_program(chained_call.program_id) else {
                return Err(LeeError::InvalidInput("Unknown program".into()));
            };
            let program = Program::new_unchecked(
                chained_call.program_id,
                Cow::Owned(program_account.data.to_vec()),
            );

            let authorized_pdas =
                compute_public_authorized_pdas(caller_data.program_id, &chained_call.pda_seeds);

            // Account is authorized if it is either in the caller's authorized accounts or in the
            // list of PDAs the caller has authorized.
            let is_authorized = |account_id: &AccountId| {
                authorized_pdas.contains(account_id)
                    || caller_data.authorized_accounts.contains(account_id)
            };

            // The caller only names which accounts to call with (`accounts`); resolve their
            // actual values from the protocol's own tracked state, not from anything it asserts.
            let real_pre_states: Vec<AccountWithMetadata> = chained_call
                .accounts
                .iter()
                .map(|account_id| {
                    let account = overlaid_account(state, &state_diff, *account_id);
                    AccountWithMetadata::new(account, is_authorized(account_id), *account_id)
                })
                .collect();

            debug!(
                "Program {:?} pre_states: {:?}, instruction_data: {:?}",
                chained_call.program_id, real_pre_states, chained_call.instruction_data
            );
            let program_output = program.execute(
                caller_data.program_id,
                &real_pre_states,
                &chained_call.instruction_data,
            )?;
            debug!(
                "Program {:?} output: {:?}",
                chained_call.program_id, program_output
            );

            // The caller only names accounts; the protocol delivers them. The callee's journal is
            // the only evidence of what it ran on, so it must account for exactly the named
            // accounts, in order. Only a real caller->callee edge is bound: the entry program is
            // free to commit its own order or subset of what the transaction declared, which is
            // what the circuit's `top_level_pre_state_refs` encodes.
            ensure!(
                caller_data.program_id.is_none()
                    || pre_states_match_refs(&chained_call.accounts, &program_output.pre_states),
                InvalidProgramBehaviorError::ChainedCallAccountsMismatch {
                    program_id: chained_call.program_id
                }
            );

            for pre in &program_output.pre_states {
                let account_id = pre.account_id;
                // Check that the program output pre_states coincide with the values in the public
                // state or with any modifications to those values during the chain of calls.
                let expected_pre = overlaid_account(state, &state_diff, account_id);
                ensure!(
                    pre.account == expected_pre,
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(expected_pre),
                        actual: Box::new(pre.account.clone())
                    }
                );

                // Check that the program output pre_states marked as authorized are indeed
                // authorized, and vice-versa.
                let is_indeed_authorized = is_authorized(&account_id);
                ensure!(
                    !pre.is_authorized || is_indeed_authorized,
                    InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id }
                );
                ensure!(
                    pre.is_authorized || !is_indeed_authorized,
                    InvalidProgramBehaviorError::AuthorizedAccountMarkedAsNotAuthorized {
                        account_id
                    }
                );
            }

            // Verify that the program output's self_program_id matches the expected program ID.
            ensure!(
                program_output.call.self_program_id == chained_call.program_id,
                InvalidProgramBehaviorError::MismatchedProgramId {
                    expected: chained_call.program_id,
                    actual: program_output.call.self_program_id
                }
            );

            // Verify that the program output's caller_program_id matches the actual caller.
            ensure!(
                program_output.call.caller_program_id == caller_data.program_id,
                InvalidProgramBehaviorError::MismatchedCallerProgramId {
                    expected: caller_data.program_id,
                    actual: program_output.call.caller_program_id,
                }
            );

            // Verify execution corresponds to a well-behaved program.
            // See the # Programs section for the definition of the `validate_execution` method.
            validate_execution(
                &program_output.pre_states,
                &program_output.effects.post_states,
                chained_call.program_id,
            )
            .map_err(InvalidProgramBehaviorError::ExecutionValidationFailed)?;

            // Verify validity window
            ensure!(
                program_output
                    .effects
                    .block_validity_window
                    .is_valid_for(block_id)
                    && program_output
                        .effects
                        .timestamp_validity_window
                        .is_valid_for(timestamp),
                LeeError::OutOfValidityWindow
            );

            for (pre, diff_output) in program_output
                .pre_states
                .iter()
                .zip(&program_output.effects.post_states)
            {
                let account_id = pre.account_id;
                let diff = diff_output.diff();

                let balance = apply_balance_diff(pre.account.balance, diff.diff_balance)
                    .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?;

                let data = diff
                    .diff_data
                    .clone()
                    .unwrap_or_else(|| pre.account.data.clone());

                // Owner is inherited unless a claim overrides it (AccountDiff carries no
                // ownership).
                let program_owner = if let Some(claim) = diff_output.claim() {
                    // The invoked program can only claim accounts with default program id.
                    ensure!(
                        pre.account.program_owner == DEFAULT_PROGRAM_OWNER,
                        InvalidProgramBehaviorError::ClaimedNonDefaultAccount { account_id }
                    );

                    match claim {
                        Claim::Authorized => {
                            // The program can only claim accounts that were authorized by the
                            // signer.
                            ensure!(
                                pre.is_authorized,
                                InvalidProgramBehaviorError::ClaimedUnauthorizedAccount {
                                    account_id
                                }
                            );
                        }
                        Claim::Pda(seed) => {
                            // The program can only claim accounts that correspond to the PDAs it
                            // is authorized to claim. The public-execution path only sees public
                            // accounts, so the public-PDA derivation is the correct formula here.
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

                    AccountId::from(chained_call.program_id)
                } else {
                    pre.account.program_owner
                };

                state_diff.insert(
                    account_id,
                    Account {
                        program_owner,
                        balance,
                        data,
                        nonce: pre.account.nonce,
                    },
                );
            }

            // Source from `program_output.pre_states` (the callee's own checked echo), not
            // `chained_call.accounts` (bare ids the caller supplied, carrying no
            // authorization claim at all) — the loop above already gates program_output's
            // `is_authorized` via the `!pre.is_authorized || is_indeed_authorized` check.
            //
            // Union with the caller's authorized set so that authorization is monotonically
            // growing: once an account is authorized at any point in the chain it remains
            // authorized for all subsequent calls.
            let mut authorized_accounts = caller_data.authorized_accounts;
            authorized_accounts.extend(
                program_output
                    .pre_states
                    .iter()
                    .filter(|pre| pre.is_authorized)
                    .map(|pre| pre.account_id),
            );
            for new_call in program_output.effects.chained_calls.into_iter().rev() {
                chained_calls.push_front((
                    new_call,
                    CallerData {
                        program_id: Some(chained_call.program_id),
                        authorized_accounts: authorized_accounts.clone(),
                    },
                ));
            }

            chain_calls_counter = chain_calls_counter
                .checked_add(1)
                .expect("we check the max depth at the beginning of the loop");
        }

        // Check that all modified uninitialized accounts where claimed
        for (account_id, post) in state_diff.iter().filter_map(|(account_id, post)| {
            let pre = state.get_account_by_id(*account_id);
            if pre.program_owner != DEFAULT_PROGRAM_OWNER {
                return None;
            }
            if pre == *post {
                return None;
            }
            Some((*account_id, post))
        }) {
            ensure!(
                post.program_owner != DEFAULT_PROGRAM_OWNER,
                InvalidProgramBehaviorError::DefaultAccountModifiedWithoutClaim { account_id }
            );
        }

        // Every account the caller declared as part of the transaction must appear in the final
        // diff.
        for account_id in &message.account_ids {
            ensure!(
                state_diff.contains_key(account_id),
                InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput {
                    account_id: *account_id
                }
            );
        }

        Ok(Self(StateDiff {
            signer_account_ids,
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
    ) -> Result<Self, LeeError> {
        let message = &tx.message;
        let witness_set = &tx.witness_set;
        let commitments = message.commitments();
        let nullifiers = message.nullifiers();
        let public_account_ids = message.public_account_ids();

        // 1. Commitments or nullifiers are non empty
        ensure!(
            !message.private_actions.is_empty(),
            LeeError::InvalidInput(
                "Empty commitments and empty nullifiers found in message".into(),
            )
        );

        // 2. Check there are no duplicate account_ids in the public_account_ids list.
        ensure!(
            n_unique(&public_account_ids) == public_account_ids.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into())
        );

        // Check there are no duplicate nullifiers in the new_nullifiers list
        ensure!(
            n_unique(&nullifiers.iter().map(|(n, _)| n).collect::<Vec<_>>()) == nullifiers.len(),
            LeeError::InvalidInput("Duplicate nullifiers found in message".into())
        );

        // Check there are no duplicate commitments in the new_commitments list
        ensure!(
            n_unique(&commitments) == commitments.len(),
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
        check_signer_nonces(state, &signer_account_ids, &message.nonces)?;

        // Verify validity window
        ensure!(
            message.block_validity_window.is_valid_for(block_id)
                && message.timestamp_validity_window.is_valid_for(timestamp),
            LeeError::OutOfValidityWindow
        );

        // Build pre_states for proof verification
        let public_pre_states: Vec<_> = public_account_ids
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
        state.check_commitments_are_new(&commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&nullifiers)?;

        let public_diff = message
            .public_actions
            .iter()
            .map(|action| (action.account_id, action.post_state.clone()))
            .collect();
        let new_nullifiers = nullifiers.iter().map(|(nullifier, _)| *nullifier).collect();

        Ok(Self(StateDiff {
            signer_account_ids,
            public_diff,
            new_commitments: commitments,
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
        if state.get_program(program.id()).is_some() {
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
    check_signer_nonces(state, &signer_account_ids, &message.nonces)?;

    Ok(signer_account_ids)
}

fn check_privacy_preserving_circuit_proof_is_valid(
    proof: &Proof,
    public_pre_states: &[AccountWithMetadata],
    message: &Message,
) -> Result<(), LeeError> {
    let output = PrivacyPreservingCircuitOutput {
        public_actions: public_pre_states
            .iter()
            .cloned()
            .zip(&message.public_actions)
            .map(|(pre, action)| PublicAction {
                pre,
                post: action.post_state.clone(),
            })
            .collect(),
        private_actions: message.private_actions.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
    };
    proof
        .is_valid_for(&output)
        .then_some(())
        .ok_or(LeeError::InvalidPrivacyPreservingProof)
}

fn overlaid_account(
    state: &V03State,
    state_diff: &HashMap<AccountId, Account>,
    account_id: AccountId,
) -> Account {
    state_diff
        .get(&account_id)
        .cloned()
        .unwrap_or_else(|| state.get_account_by_id(account_id))
}

fn check_signer_nonces(
    state: &V03State,
    account_ids: &[AccountId],
    nonces: &[Nonce],
) -> Result<(), LeeError> {
    for (account_id, nonce) in account_ids.iter().zip(nonces) {
        let current_nonce = state.get_account_by_id(*account_id).nonce;
        ensure!(
            current_nonce == *nonce,
            LeeError::InvalidInput("Nonce mismatch".into())
        );
    }
    Ok(())
}

fn n_unique<T: Eq + Hash>(data: &[T]) -> usize {
    let set: HashSet<&T> = data.iter().collect();
    set.len()
}

fn pre_states_match_refs(pre_state_refs: &[AccountId], pre_states: &[AccountWithMetadata]) -> bool {
    pre_state_refs
        .iter()
        .eq(pre_states.iter().map(|pre| &pre.account_id))
}

#[cfg(test)]
mod tests;
