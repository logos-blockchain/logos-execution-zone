use std::collections::{HashMap, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    MembershipProof, NullifierPublicKey, NullifierSecretKey, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput, SharedSecretKey,
    account::AccountWithMetadata,
    program::{ChainedCall, InstructionData, ProgramId, ProgramOutput},
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    error::NssaError,
    program::Program,
    program_methods::{PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID},
    state::MAX_NUMBER_CHAINED_CALLS,
};

/// Proof of the privacy preserving execution circuit.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proof(pub(crate) Vec<u8>);

impl Proof {
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub const fn from_inner(inner: Vec<u8>) -> Self {
        Self(inner)
    }

    pub(crate) fn is_valid_for(&self, circuit_output: &PrivacyPreservingCircuitOutput) -> bool {
        let inner: InnerReceipt = borsh::from_slice(&self.0).unwrap();
        let receipt = Receipt::new(inner, circuit_output.to_bytes());
        receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID).is_ok()
    }
}

#[derive(Clone)]
pub struct ProgramWithDependencies {
    pub program: Program,
    // TODO: avoid having a copy of the bytecode of each dependency.
    pub dependencies: HashMap<ProgramId, Program>,
}

impl ProgramWithDependencies {
    #[must_use]
    pub const fn new(program: Program, dependencies: HashMap<ProgramId, Program>) -> Self {
        Self {
            program,
            dependencies,
        }
    }
}

impl From<Program> for ProgramWithDependencies {
    fn from(program: Program) -> Self {
        Self::new(program, HashMap::new())
    }
}

/// Generates a proof of the execution of a NSSA program inside the privacy preserving execution
/// circuit.
#[expect(clippy::too_many_arguments, reason = "TODO: fix later")]
pub fn execute_and_prove(
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
    visibility_mask: Vec<u8>,
    private_account_nonces: Vec<u128>,
    private_account_keys: Vec<(NullifierPublicKey, SharedSecretKey)>,
    private_account_nsks: Vec<NullifierSecretKey>,
    private_account_membership_proofs: Vec<Option<MembershipProof>>,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), NssaError> {
    let ProgramWithDependencies {
        program: initial_program,
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();

    let initial_call = ChainedCall {
        program_id: initial_program.id(),
        instruction_data,
        pre_states,
        pda_seeds: vec![],
    };

    let mut chained_calls = VecDeque::from_iter([(initial_call, initial_program)]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program)) = chained_calls.pop_front() {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(NssaError::MaxChainedCallsDepthExceeded);
        }

        let inner_receipt = execute_and_prove_program(
            program,
            &chained_call.pre_states,
            &chained_call.instruction_data,
        )?;

        let program_output: ProgramOutput = inner_receipt
            .journal
            .decode()
            .map_err(|e| NssaError::ProgramOutputDeserializationError(e.to_string()))?;

        // TODO: remove clone
        program_outputs.push(program_output.clone());

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in program_output.chained_calls.into_iter().rev() {
            let next_program = dependencies
                .get(&new_call.program_id)
                .ok_or(NssaError::InvalidProgramBehavior)?;
            chained_calls.push_front((new_call, next_program));
        }

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("we check the max depth at the beginning of the loop");
    }

    let circuit_input = PrivacyPreservingCircuitInput {
        program_outputs,
        visibility_mask,
        private_account_nonces,
        private_account_keys,
        private_account_nsks,
        private_account_membership_proofs,
        program_id: program_with_dependencies.program.id(),
    };

    env_builder.write(&circuit_input).unwrap();
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &opts)
        .map_err(|e| NssaError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);

    let circuit_output: PrivacyPreservingCircuitOutput = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|e| NssaError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((circuit_output, proof))
}

fn execute_and_prove_program(
    program: &Program,
    pre_states: &[AccountWithMetadata],
    instruction_data: &InstructionData,
) -> Result<Receipt, NssaError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    Program::write_inputs(pre_states, instruction_data, &mut env_builder)?;
    let env = env_builder.build().unwrap();

    // Prove the program
    let prover = default_prover();
    Ok(prover
        .prove(env, program.elf())
        .map_err(|e| NssaError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

    use nssa_core::{
        Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, Nullifier,
        account::{Account, AccountId, AccountWithMetadata, data::Data},
    };

    use super::*;
    use crate::{
        privacy_preserving_transaction::circuit::execute_and_prove,
        program::Program,
        state::{
            CommitmentSet,
            tests::{test_private_account_keys_1, test_private_account_keys_2},
        },
    };

    #[test]
    fn prove_privacy_preserving_execution_circuit_public_and_private_pre_accounts() {
        let recipient_keys = test_private_account_keys_1();
        let program = Program::authenticated_transfer_program();
        let sender = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            AccountId::from(&recipient_keys.npk()),
        );

        let balance_to_move: u128 = 37;

        let expected_sender_post = Account {
            program_owner: program.id(),
            balance: 100 - balance_to_move,
            nonce: 0,
            data: Data::default(),
        };

        let expected_recipient_post = Account {
            program_owner: program.id(),
            balance: balance_to_move,
            nonce: 0xdead_beef,
            data: Data::default(),
        };

        let expected_sender_pre = sender.clone();

        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &recipient_keys.vpk());

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![0, 2],
            vec![0xdead_beef],
            vec![(recipient_keys.npk(), shared_secret)],
            vec![],
            vec![None],
            &Program::authenticated_transfer_program().into(),
        )
        .unwrap();

        assert!(proof.is_valid_for(&output));

        let [sender_pre] = output.public_pre_states.try_into().unwrap();
        let [sender_post] = output.public_post_states.try_into().unwrap();
        assert_eq!(sender_pre, expected_sender_pre);
        assert_eq!(sender_post, expected_sender_post);
        assert_eq!(output.new_commitments.len(), 1);
        assert_eq!(output.new_nullifiers.len(), 1);
        assert_eq!(output.ciphertexts.len(), 1);

        let recipient_post = EncryptionScheme::decrypt(
            &output.ciphertexts[0],
            &shared_secret,
            &output.new_commitments[0],
            0,
        )
        .unwrap();
        assert_eq!(recipient_post, expected_recipient_post);
    }

    #[test]
    fn prove_privacy_preserving_execution_circuit_fully_private() {
        let program = Program::authenticated_transfer_program();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();

        let sender_pre = AccountWithMetadata::new(
            Account {
                balance: 100,
                nonce: 0xdead_beef,
                program_owner: program.id(),
                data: Data::default(),
            },
            true,
            AccountId::from(&sender_keys.npk()),
        );
        let commitment_sender = Commitment::new(&sender_keys.npk(), &sender_pre.account);

        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            AccountId::from(&recipient_keys.npk()),
        );
        let balance_to_move: u128 = 37;

        let mut commitment_set = CommitmentSet::with_capacity(2);
        commitment_set.extend(std::slice::from_ref(&commitment_sender));

        let expected_new_nullifiers = vec![
            (
                Nullifier::for_account_update(&commitment_sender, &sender_keys.nsk),
                commitment_set.digest(),
            ),
            (
                Nullifier::for_account_initialization(&recipient_keys.npk()),
                DUMMY_COMMITMENT_HASH,
            ),
        ];

        let program = Program::authenticated_transfer_program();

        let expected_private_account_1 = Account {
            program_owner: program.id(),
            balance: 100 - balance_to_move,
            nonce: 0xdead_beef1,
            ..Default::default()
        };
        let expected_private_account_2 = Account {
            program_owner: program.id(),
            balance: balance_to_move,
            nonce: 0xdead_beef2,
            ..Default::default()
        };
        let expected_new_commitments = vec![
            Commitment::new(&sender_keys.npk(), &expected_private_account_1),
            Commitment::new(&recipient_keys.npk(), &expected_private_account_2),
        ];

        let esk_1 = [3; 32];
        let shared_secret_1 = SharedSecretKey::new(&esk_1, &sender_keys.vpk());

        let esk_2 = [5; 32];
        let shared_secret_2 = SharedSecretKey::new(&esk_2, &recipient_keys.vpk());

        let (output, proof) = execute_and_prove(
            vec![sender_pre, recipient],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![1, 2],
            vec![0xdead_beef1, 0xdead_beef2],
            vec![
                (sender_keys.npk(), shared_secret_1),
                (recipient_keys.npk(), shared_secret_2),
            ],
            vec![sender_keys.nsk],
            vec![commitment_set.get_proof_for(&commitment_sender), None],
            &program.into(),
        )
        .unwrap();

        assert!(proof.is_valid_for(&output));
        assert!(output.public_pre_states.is_empty());
        assert!(output.public_post_states.is_empty());
        assert_eq!(output.new_commitments, expected_new_commitments);
        assert_eq!(output.new_nullifiers, expected_new_nullifiers);
        assert_eq!(output.ciphertexts.len(), 2);

        let sender_post = EncryptionScheme::decrypt(
            &output.ciphertexts[0],
            &shared_secret_1,
            &expected_new_commitments[0],
            0,
        )
        .unwrap();
        assert_eq!(sender_post, expected_private_account_1);

        let recipient_post = EncryptionScheme::decrypt(
            &output.ciphertexts[1],
            &shared_secret_2,
            &expected_new_commitments[1],
            1,
        )
        .unwrap();
        assert_eq!(recipient_post, expected_private_account_2);
    }
}
