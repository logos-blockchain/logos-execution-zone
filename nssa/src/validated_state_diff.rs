use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
};

use log::debug;
use nssa_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, Timestamp,
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        ChainedCall, Claim, DEFAULT_PROGRAM_ID, ProgramId, compute_public_authorized_pdas,
        validate_execution,
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
        let message = tx.message();
        let witness_set = tx.witness_set();

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

        let signer_account_ids = tx.signer_account_ids();
        // Check nonces corresponds to the current nonces on the public state.
        for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
            let current_nonce = state.get_account_by_id(*account_id).nonce;
            ensure!(
                current_nonce == *nonce,
                NssaError::InvalidInput("Nonce mismatch".into())
            );
        }

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

        let mut state_diff: HashMap<AccountId, Account> = HashMap::new();

        let initial_call = ChainedCall {
            program_id: message.program_id,
            instruction_data: message.instruction_data.clone(),
            pre_states: input_pre_states,
            pda_seeds: vec![],
        };

        #[expect(
            clippy::items_after_statements,
            reason = "More readable to keep it behind the place where it's used"
        )]
        #[derive(Debug)]
        struct CallerData {
            program_id: Option<ProgramId>,
            authorized_accounts: HashSet<AccountId>,
        }

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
                NssaError::MaxChainedCallsDepthExceeded
            );

            // Check that the `program_id` corresponds to a deployed program
            let Some(program) = state.programs().get(&chained_call.program_id) else {
                return Err(NssaError::InvalidInput("Unknown program".into()));
            };

            debug!(
                "Program {:?} pre_states: {:?}, instruction_data: {:?}",
                chained_call.program_id, chained_call.pre_states, chained_call.instruction_data
            );
            let mut program_output = program.execute(
                caller_data.program_id,
                &chained_call.pre_states,
                &chained_call.instruction_data,
            )?;
            debug!(
                "Program {:?} output: {:?}",
                chained_call.program_id, program_output
            );

            let authorized_pdas =
                compute_public_authorized_pdas(caller_data.program_id, &chained_call.pda_seeds);

            // Account is authorized if it is either in the caller's authorized accounts or in the
            // list of PDAs the caller has authorized.
            let is_authorized = |account_id: &AccountId| {
                authorized_pdas.contains(account_id)
                    || caller_data.authorized_accounts.contains(account_id)
            };

            for pre in &program_output.pre_states {
                let account_id = pre.account_id;
                // Check that the program output pre_states coincide with the values in the public
                // state or with any modifications to those values during the chain of calls.
                let expected_pre = state_diff
                    .get(&account_id)
                    .cloned()
                    .unwrap_or_else(|| state.get_account_by_id(account_id));
                ensure!(
                    pre.account == expected_pre,
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(expected_pre),
                        actual: Box::new(pre.account.clone())
                    }
                );

                // Check that the program output pre_states marked as authorized are indeed
                // authorized.
                let is_indeed_authorized = is_authorized(&account_id);
                ensure!(
                    !pre.is_authorized || is_indeed_authorized,
                    InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id }
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
                program_output.caller_program_id == caller_data.program_id,
                InvalidProgramBehaviorError::MismatchedCallerProgramId {
                    expected: caller_data.program_id,
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
                program_output.block_validity_window.is_valid_for(block_id)
                    && program_output
                        .timestamp_validity_window
                        .is_valid_for(timestamp),
                NssaError::OutOfValidityWindow
            );

            for (i, post) in program_output.post_states.iter_mut().enumerate() {
                let Some(claim) = post.required_claim() else {
                    continue;
                };
                let pre = &program_output.pre_states[i];
                let account_id = pre.account_id;

                // The invoked program can only claim accounts with default program id.
                ensure!(
                    post.account().program_owner == DEFAULT_PROGRAM_ID,
                    InvalidProgramBehaviorError::ClaimedNonDefaultAccount { account_id }
                );

                match claim {
                    Claim::Authorized => {
                        // The program can only claim accounts that were authorized by the signer.
                        ensure!(
                            pre.is_authorized,
                            InvalidProgramBehaviorError::ClaimedUnauthorizedAccount { account_id }
                        );
                    }
                    Claim::Pda(seed) => {
                        // The program can only claim accounts that correspond to the PDAs it is
                        // authorized to claim. The public-execution path only sees public
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

                post.account_mut().program_owner = chained_call.program_id;
            }

            // Update the state diff
            for (pre, post) in program_output
                .pre_states
                .iter()
                .zip(program_output.post_states.iter())
            {
                state_diff.insert(pre.account_id, post.account().clone());
            }

            // Source from `program_output.pre_states`, not `chained_call.pre_states`:
            // the loop above already gates program_output's `is_authorized` via the
            // `!pre.is_authorized || is_indeed_authorized` check, while `chained_call.
            // pre_states` is caller-controlled and can be forged (audit-issue 91).
            let authorized_accounts: HashSet<_> = program_output
                .pre_states
                .iter()
                .filter(|pre| pre.is_authorized)
                .map(|pre| pre.account_id)
                .collect();
            for new_call in program_output.chained_calls.into_iter().rev() {
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

#[cfg(test)]
mod tests {
    use nssa_core::account::{AccountId, Nonce};

    use crate::{
        PrivateKey, PublicKey, V03State,
        error::{InvalidProgramBehaviorError, NssaError},
        program::Program,
        public_transaction::{Message, WitnessSet},
        validated_state_diff::ValidatedStateDiff,
    };

    /// Privacy-path version of the authorization-injection attack. The test passes when the
    /// attack is rejected and the victim's balance is left untouched.
    ///
    /// `execute_and_prove` succeeds because each inner receipt is individually valid and the
    /// outer circuit faithfully commits whatever the attacker's program output says, including
    /// `victim(is_authorized=true)`. The circuit has no access to chain state and cannot know
    /// the victim never signed.
    ///
    /// The host-side validator is what catches the attack: it independently reconstructs
    /// `public_pre_states` from chain state using `signer_account_ids.contains(victim_id) = false`,
    /// so it expects `victim(is_authorized=false)`. The committed journal and the reconstructed
    /// expected output diverge, `receipt.verify` fails, and `from_privacy_preserving_transaction`
    /// returns an error before any state is applied.
    #[test]
    fn privacy_malicious_programs_cannot_drain_public_victim() {
        use nssa_core::{
            Commitment, InputAccountIdentity, SharedSecretKey,
            account::{Account, AccountWithMetadata},
            encryption::EphemeralPublicKey,
        };

        use crate::{
            PrivacyPreservingTransaction,
            privacy_preserving_transaction::{
                circuit::{ProgramWithDependencies, execute_and_prove},
                message::Message,
                witness_set::WitnessSet,
            },
            state::{CommitmentSet, tests::test_private_account_keys_1},
        };

        type InjectorInstruction = (
            nssa_core::program::ProgramId, // p2_id
            nssa_core::program::ProgramId, // auth_transfer_id
            [u8; 32],                      // victim_id_raw
            u128,                          // victim_balance
            u128,                          // victim_nonce
            nssa_core::program::ProgramId, // victim_program_owner
            [u8; 32],                      // recipient_id_raw
            u128,                          // amount
        );

        // Attacker controls a private account.
        let attacker_keys = test_private_account_keys_1();
        let attacker_id = AccountId::for_regular_private_account(&attacker_keys.npk(), 0);
        let attacker_esk = [12_u8; 32];
        let attacker_ssk = SharedSecretKey::new(attacker_esk, &attacker_keys.vpk());
        let attacker_epk = EphemeralPublicKey::from_scalar(attacker_esk);

        let victim_id = AccountId::new([20_u8; 32]);
        let recipient_id = AccountId::new([42_u8; 32]);
        let victim_balance = 5_000_u128;

        // genesis sets program_owner = authenticated_transfer_program.id() on all accounts.
        let mut state = V03State::new_with_genesis_accounts(
            &[(victim_id, victim_balance), (recipient_id, 0)],
            vec![],
            0,
        );
        state.insert_program(Program::malicious_injector());
        state.insert_program(Program::malicious_launderer());

        // Build attacker's private account and its local commitment tree.
        let attacker_account = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: 100,
            ..Account::default()
        };
        let attacker_commitment = Commitment::new(&attacker_id, &attacker_account);
        let mut commitment_set = CommitmentSet::with_capacity(1);
        commitment_set.extend(std::slice::from_ref(&attacker_commitment));
        let membership_proof = commitment_set
            .get_proof_for(&attacker_commitment)
            .expect("attacker commitment must be in the set");

        let attacker_pre = AccountWithMetadata::new(attacker_account, true, attacker_id);

        let victim_account = state.get_account_by_id(victim_id);
        let instruction: InjectorInstruction = (
            Program::malicious_launderer().id(),
            Program::authenticated_transfer_program().id(),
            *victim_id.value(),
            victim_account.balance,
            victim_account.nonce.0,
            victim_account.program_owner,
            *recipient_id.value(),
            victim_balance,
        );
        let instruction_data = Program::serialize_instruction(instruction).unwrap();

        let p2 = Program::malicious_launderer();
        let at = Program::authenticated_transfer_program();
        let program_with_deps = ProgramWithDependencies::new(
            Program::malicious_injector(),
            [(p2.id(), p2), (at.id(), at)].into(),
        );

        // account_identities order must match self.pre_states as built by the circuit:
        //   [0] attacker — first seen in P1's program_output.pre_states
        //   [1] victim   — first seen in authenticated_transfer's program_output.pre_states
        //   [2] recipient — first seen in authenticated_transfer's program_output.pre_states
        let account_identities = vec![
            InputAccountIdentity::PrivateAuthorizedUpdate {
                ssk: attacker_ssk,
                nsk: attacker_keys.nsk,
                membership_proof,
                identifier: 0,
            },
            InputAccountIdentity::Public, // victim
            InputAccountIdentity::Public, // recipient
        ];

        // execute_and_prove succeeds: all inner receipts are valid.
        // The outer circuit commits victim(is_authorized=true) to its journal.
        let (circuit_output, proof) = execute_and_prove(
            vec![attacker_pre],
            instruction_data,
            account_identities,
            &program_with_deps,
        )
        .expect("execute_and_prove should succeed \u{2014} the programs execute correctly");

        // public_account_ids lists the Public entries from account_identities, in order.
        // The single ciphertext belongs to attacker's private account update.
        let message = Message::try_from_circuit_output(
            vec![victim_id, recipient_id],
            vec![], // no public signers, no nonces
            vec![(attacker_keys.npk(), attacker_keys.vpk(), attacker_epk)],
            circuit_output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]); // no signatures
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

        assert!(
            matches!(result, Err(NssaError::InvalidPrivacyPreservingProof)),
            "attack privacy transaction should be rejected with InvalidPrivacyPreservingProof"
        );
        assert_eq!(state.get_account_by_id(victim_id).balance, victim_balance);
        assert_eq!(state.get_account_by_id(recipient_id).balance, 0);
    }

    /// Private-victim variant of the authorization-injection attack. The test passes when the
    /// attack is rejected and the recipient's balance remains zero.
    ///
    /// After the circuit's Vacant branch accepts the injected `victim(is_authorized=true)`
    /// verbatim, the attacker must choose how to declare the victim in `account_identities`.
    /// There are two routes, both closed:
    ///
    /// - **mask=1 (`PrivateAuthorizedUpdate`)**: the circuit derives `account_id =
    ///   AccountId::for_regular_private_account(&npk_from(nsk), identifier)` and asserts it matches
    ///   `pre_state.account_id`. Passing this check requires the victim's `nsk`, which the attacker
    ///   does not have. `execute_and_prove` panics inside the ZKVM and no proof is produced.
    ///
    /// - **mask=0 (`Public`)**: the circuit places the account in `public_pre_states` and
    ///   `execute_and_prove` succeeds. The host-side validator then reconstructs
    ///   `public_pre_states` from chain state; `state.get_account_by_id(victim_id)` returns the
    ///   default account (balance=0) because the victim has no public state entry. The committed
    ///   journal and the reconstructed expected output diverge, `receipt.verify` fails, and
    ///   `from_privacy_preserving_transaction` returns an error before any state is applied. This
    ///   test exercises this route.
    #[test]
    fn privacy_malicious_programs_cannot_drain_private_victim() {
        use nssa_core::{
            Commitment, InputAccountIdentity, SharedSecretKey,
            account::{Account, AccountWithMetadata},
            encryption::EphemeralPublicKey,
        };

        use crate::{
            PrivacyPreservingTransaction,
            privacy_preserving_transaction::{
                circuit::{ProgramWithDependencies, execute_and_prove},
                message::Message,
                witness_set::WitnessSet,
            },
            state::{
                CommitmentSet,
                tests::{test_private_account_keys_1, test_private_account_keys_2},
            },
        };

        type InjectorInstruction = (
            nssa_core::program::ProgramId, // p2_id
            nssa_core::program::ProgramId, // auth_transfer_id
            [u8; 32],                      // victim_id_raw
            u128,                          // victim_balance
            u128,                          // victim_nonce
            nssa_core::program::ProgramId, // victim_program_owner
            [u8; 32],                      // recipient_id_raw
            u128,                          // amount
        );

        // Attacker controls a private account.
        let attacker_keys = test_private_account_keys_1();
        let attacker_id = AccountId::for_regular_private_account(&attacker_keys.npk(), 0);
        let attacker_esk = [12_u8; 32];
        let attacker_ssk = SharedSecretKey::new(attacker_esk, &attacker_keys.vpk());
        let attacker_epk = EphemeralPublicKey::from_scalar(attacker_esk);

        // Victim is a private account — not registered in public chain state.
        let victim_keys = test_private_account_keys_2();
        let victim_id = AccountId::for_regular_private_account(&victim_keys.npk(), 0);
        let victim_balance = 5_000_u128;

        let recipient_id = AccountId::new([42_u8; 32]);

        // Victim has no public state entry; only recipient is registered at genesis.
        let mut state = V03State::new_with_genesis_accounts(&[(recipient_id, 0)], vec![], 0);
        state.insert_program(Program::malicious_injector());
        state.insert_program(Program::malicious_launderer());

        // Build attacker's private account and its local commitment tree.
        let attacker_account = Account {
            program_owner: Program::authenticated_transfer_program().id(),
            balance: 100,
            ..Account::default()
        };
        let attacker_commitment = Commitment::new(&attacker_id, &attacker_account);
        let mut commitment_set = CommitmentSet::with_capacity(1);
        commitment_set.extend(std::slice::from_ref(&attacker_commitment));
        let membership_proof = commitment_set
            .get_proof_for(&attacker_commitment)
            .expect("attacker commitment must be in the set");

        let attacker_pre = AccountWithMetadata::new(attacker_account, true, attacker_id);

        // The attacker supplies the victim's account data directly — it cannot be read from
        // public state. The injected balance and program_owner allow authenticated_transfer
        // to succeed inside the circuit, which has no access to chain state and cannot detect
        // that these values are fabricated.
        let instruction: InjectorInstruction = (
            Program::malicious_launderer().id(),
            Program::authenticated_transfer_program().id(),
            *victim_id.value(),
            victim_balance,
            0_u128,                                         // nonce
            Program::authenticated_transfer_program().id(), // program_owner
            *recipient_id.value(),
            victim_balance,
        );
        let instruction_data = Program::serialize_instruction(instruction).unwrap();

        let p2 = Program::malicious_launderer();
        let at = Program::authenticated_transfer_program();
        let program_with_deps = ProgramWithDependencies::new(
            Program::malicious_injector(),
            [(p2.id(), p2), (at.id(), at)].into(),
        );

        // account_identities order must match self.pre_states as built by the circuit:
        //   [0] attacker  — first seen in P1's program_output.pre_states
        //   [1] victim    — first seen in authenticated_transfer's program_output.pre_states
        //   [2] recipient — first seen in authenticated_transfer's program_output.pre_states
        //
        // Victim is marked Public: the attacker has no nsk for the victim's private account,
        // so PrivateAuthorizedUpdate is not an option.
        let account_identities = vec![
            InputAccountIdentity::PrivateAuthorizedUpdate {
                ssk: attacker_ssk,
                nsk: attacker_keys.nsk,
                membership_proof,
                identifier: 0,
            },
            InputAccountIdentity::Public, // victim — attacker lacks victim's nsk
            InputAccountIdentity::Public, // recipient
        ];

        // execute_and_prove succeeds: authenticated_transfer runs against the injected
        // victim(balance=5000, is_authorized=true) and produces valid inner receipts.
        // The outer circuit commits victim(is_authorized=true) to public_pre_states.
        let (circuit_output, proof) = execute_and_prove(
            vec![attacker_pre],
            instruction_data,
            account_identities,
            &program_with_deps,
        )
        .expect("execute_and_prove should succeed \u{2014} the programs execute correctly");

        // public_account_ids lists the Public entries from account_identities, in order.
        // The single ciphertext belongs to attacker's private account update.
        let message = Message::try_from_circuit_output(
            vec![victim_id, recipient_id],
            vec![], // no public signers, no nonces
            vec![(attacker_keys.npk(), attacker_keys.vpk(), attacker_epk)],
            circuit_output,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]); // no signatures
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

        assert!(
            matches!(result, Err(NssaError::InvalidPrivacyPreservingProof)),
            "attack on private victim should be rejected with InvalidPrivacyPreservingProof"
        );
        // Victim has no public balance to check; confirming the recipient received nothing
        // is sufficient to show no funds moved.
        assert_eq!(state.get_account_by_id(recipient_id).balance, 0);
    }

    /// Two malicious programs (injector + launderer) attempt to drain a victim's balance
    /// without the victim signing anything. The test passes when the attack is rejected
    /// and the victim's balance is left untouched.
    ///
    /// Attack flow:
    ///   Transaction (attacker signs) → P1 (`malicious_injector`)
    ///     → injects `victim(is_authorized=true)` into chained-call `pre_states` for P2
    ///   P2 (`malicious_launderer`)
    ///     → outputs empty pre/post states, forwarding the forged flag to `authenticated_transfer`
    ///     → if `authorized_accounts` were built from the injected `pre_states`,
    ///       `{victim}.contains(victim)` would pass and the transfer would execute.
    ///
    /// The validator must reject this: `authorized_accounts` must be derived from the
    /// parent program's own validated `program_output.pre_states`, not from the chained-call
    /// input, so a forged `is_authorized=true` flag is never trusted.
    #[test]
    fn malicious_programs_cannot_drain_victim_without_signature() {
        // p2_id, auth_transfer_id, victim_id_raw, victim_balance, victim_nonce,
        // victim_program_owner, recipient_id_raw, amount.
        // Primitives only — AccountId/Account cannot round-trip through instruction_data
        // via risc0_zkvm::serde (SerializeDisplay issue).
        type InjectorInstruction = (
            nssa_core::program::ProgramId, // p2_id
            nssa_core::program::ProgramId, // auth_transfer_id
            [u8; 32],                      // victim_id_raw
            u128,                          // victim_balance
            u128,                          // victim_nonce
            nssa_core::program::ProgramId, // victim_program_owner
            [u8; 32],                      // recipient_id_raw
            u128,                          // amount
        );

        let attacker_key = PrivateKey::try_new([10; 32]).unwrap();
        let attacker_id = AccountId::from(&PublicKey::new_from_private_key(&attacker_key));

        let victim_key = PrivateKey::try_new([20; 32]).unwrap();
        let victim_id = AccountId::from(&PublicKey::new_from_private_key(&victim_key));

        let recipient_id = AccountId::new([42; 32]);

        let victim_balance = 5_000_u128;
        let mut state = V03State::new_with_genesis_accounts(
            &[
                (attacker_id, 100),
                (victim_id, victim_balance),
                (recipient_id, 0),
            ],
            vec![],
            0,
        );

        state.insert_program(Program::malicious_injector());
        state.insert_program(Program::malicious_launderer());

        // Read victim state from chain, exactly as the attacker would.
        let victim_account = state.get_account_by_id(victim_id);

        let instruction: InjectorInstruction = (
            Program::malicious_launderer().id(),
            Program::authenticated_transfer_program().id(),
            *victim_id.value(),
            victim_account.balance,
            victim_account.nonce.0,
            victim_account.program_owner,
            *recipient_id.value(),
            victim_balance,
        );

        let message = Message::try_new(
            Program::malicious_injector().id(),
            vec![attacker_id],
            vec![Nonce(0)],
            instruction,
        )
        .unwrap();

        let witness_set = WitnessSet::for_message(&message, &[&attacker_key]);
        let tx = crate::PublicTransaction::new(message, witness_set);

        let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);

        assert!(
            matches!(
                result,
                Err(NssaError::InvalidProgramBehavior(
                    InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id }
                )) if account_id == victim_id
            ),
            "attack transaction should be rejected with InvalidAccountAuthorization for the victim"
        );

        // Confirm the victim's balance is untouched.
        let victim_balance_after = state.get_account_by_id(victim_id).balance;
        let recipient_balance_after = state.get_account_by_id(recipient_id).balance;

        assert_eq!(
            victim_balance_after, victim_balance,
            "victim balance should be unchanged"
        );
        assert_eq!(
            recipient_balance_after, 0,
            "recipient should receive nothing"
        );
    }
}
