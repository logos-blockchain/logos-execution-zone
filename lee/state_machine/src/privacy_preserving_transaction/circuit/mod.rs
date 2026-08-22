use std::collections::{HashMap, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, InputAccountIdentity, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput, ProgramImageClaim,
    account::{AccountId, AccountWithMetadata},
    program::{ChainedCall, InstructionData, ProgramOutput},
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
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
        let Ok(inner) = borsh::from_slice::<InnerReceipt>(&self.0) else {
            return false;
        };
        let receipt = Receipt::new(inner, circuit_output.to_bytes());
        receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID).is_ok()
    }
}

#[derive(Clone)]
pub struct ProgramWithDependencies {
    pub program: Program,
    /// Where `program` is dispatched at. Defaults to
    /// `program_loader_core::immutable_deploy_account_id(program.id())`, matching how every
    /// genesis-seeded builtin is actually dispatched; override via
    /// [`Self::with_program_account_id`] for a program deployed to a different PDA (e.g. a
    /// `Deploy` with a non-default `update_auth`).
    pub program_account_id: AccountId,
    // TODO: avoid having a copy of the bytecode of each dependency.
    pub dependencies: HashMap<AccountId, Program>,
}

impl ProgramWithDependencies {
    #[must_use]
    pub fn new(program: Program, dependencies: HashMap<AccountId, Program>) -> Self {
        let program_account_id = program_loader_core::immutable_deploy_account_id(program.id());
        Self {
            program,
            program_account_id,
            dependencies,
        }
    }

    /// Overrides the address `program` is dispatched at, for a program not deployed to the
    /// default immutable PDA (e.g. a `Deploy` with a non-default `update_auth`).
    #[must_use]
    pub const fn with_program_account_id(mut self, program_account_id: AccountId) -> Self {
        self.program_account_id = program_account_id;
        self
    }
}

impl From<Program> for ProgramWithDependencies {
    fn from(program: Program) -> Self {
        Self::new(program, HashMap::new())
    }
}

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
pub fn execute_and_prove(
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
    account_identities: Vec<InputAccountIdentity>,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    execute_and_prove_with_padded_inputs(
        pre_states,
        instruction_data,
        account_identities,
        vec![],
        program_with_dependencies,
    )
}

pub fn execute_and_prove_with_padded_inputs(
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
    account_identities: Vec<InputAccountIdentity>,
    dummy_inputs: Vec<DummyInput>,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let ProgramWithDependencies {
        program: initial_program,
        program_account_id: initial_program_account_id,
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();

    // Real `image_id`s for every program in this call graph whose address doesn't already
    // determine it — i.e. every `Deploy`-created program, PDA-addressed rather than
    // bijection-addressed. A legacy program needs no claim at all: `ProgramId::from(account_id)`
    // is already exact for it, by construction, with nothing to authenticate. See
    // `ProgramImageClaim` and `execution_state.rs`'s matching bijection fallback.
    let program_image_claims: Vec<ProgramImageClaim> =
        std::iter::once((*initial_program_account_id, initial_program.id()))
            .chain(
                dependencies
                    .iter()
                    .map(|(account_id, program)| (*account_id, program.id())),
            )
            .filter(|(account_id, image_id)| *account_id != AccountId::from(*image_id))
            .map(|(account_id, image_id)| ProgramImageClaim::Public {
                account_id,
                image_id,
            })
            .collect();

    let initial_call = ChainedCall {
        program_account_id: *initial_program_account_id,
        instruction_data,
        pre_states,
        pda_seeds: vec![],
    };

    let mut chained_calls = VecDeque::from_iter([(initial_call, initial_program, None)]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program, caller_account_id)) = chained_calls.pop_front() {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(LeeError::MaxChainedCallsDepthExceeded);
        }

        let inner_receipt = execute_and_prove_program(
            program,
            chained_call.program_account_id,
            caller_account_id,
            &chained_call.pre_states,
            &chained_call.instruction_data,
        )?;

        let program_output: ProgramOutput = inner_receipt
            .journal
            .decode()
            .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;

        // TODO: remove clone
        program_outputs.push(program_output.clone());

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in program_output.chained_calls.into_iter().rev() {
            let next_program = dependencies.get(&new_call.program_account_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    account_id: new_call.program_account_id,
                },
            )?;
            chained_calls.push_front((
                new_call,
                next_program,
                Some(chained_call.program_account_id),
            ));
        }

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("we check the max depth at the beginning of the loop");
    }

    let circuit_input = PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_id: program_with_dependencies.program.id(),
        dummy_inputs,
        program_image_claims,
    };

    env_builder.write(&circuit_input).unwrap();
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &opts)
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);

    let circuit_output: PrivacyPreservingCircuitOutput = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((circuit_output, proof))
}

fn execute_and_prove_program(
    program: &Program,
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: &[AccountWithMetadata],
    instruction_data: &InstructionData,
) -> Result<Receipt, LeeError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    Program::write_inputs(
        self_account_id,
        caller_account_id,
        pre_states,
        instruction_data,
        &mut env_builder,
    )?;
    let env = env_builder.build().unwrap();

    // Prove the program
    let prover = default_prover();
    Ok(prover
        .prove(env, program.elf())
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests;
