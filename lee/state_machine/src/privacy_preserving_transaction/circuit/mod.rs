use std::collections::{HashMap, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, InputAccountIdentity, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput,
    account::{AccountId, AccountWithMetadata},
    program::{
        ChainedCall, DEFAULT_PROGRAM_OWNER, InstructionData, ProgramId, ProgramOutput,
        UpdateFromDiffOutput,
    },
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
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();
    let mut update_from_diff_results = Vec::new();

    // Captured before `pre_states` moves below — this is the only place `is_authorized` is
    // caller-supplied; every later pre_state's authorization is derived inside the circuit from
    // this same list. Public accounts only: a private (`npk`/`vpk`-derived) `AccountId` could
    // never match a real signature, so including one would make it permanently unverifiable.
    let signer_account_ids: Vec<AccountId> = pre_states
        .iter()
        .zip(&account_identities)
        .filter(|(pre, identity)| pre.is_authorized && identity.is_public())
        .map(|(pre, _)| pre.account_id)
        .collect();

    let initial_call = ChainedCall {
        program_id: initial_program.id(),
        instruction_data,
        pre_states,
        pda_seeds: vec![],
    };

    let mut chained_calls = VecDeque::from_iter([(initial_call, initial_program, None)]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program, caller_program_id)) = chained_calls.pop_front() {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(LeeError::MaxChainedCallsDepthExceeded);
        }

        let inner_receipt = execute_and_prove_program(
            program,
            caller_program_id,
            &chained_call.pre_states,
            &chained_call.instruction_data,
        )?;

        let program_output: ProgramOutput = inner_receipt
            .journal
            .decode()
            .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;

        // Prove `update_from_diff` for every account this call's diff writes data to, in the
        // same order `execution_state::derive_from_outputs` will visit them, so
        // `update_from_diff_results` lines up positionally with the circuit's own traversal.
        // Dispatched to the account's *owner* program, not necessarily the caller — falls back
        // to the caller only when the account is still unclaimed (default owner).
        for (pre, diff_output) in program_output
            .pre_states
            .iter()
            .zip(&program_output.post_states)
        {
            let Some(diff_data) = diff_output.diff().diff_data.as_ref() else {
                continue;
            };
            let owner_id: ProgramId = if pre.account.program_owner == DEFAULT_PROGRAM_OWNER {
                chained_call.program_id
            } else {
                pre.account.program_owner.into()
            };
            let owner_program = if owner_id == program.id() {
                program
            } else {
                dependencies.get(&owner_id).ok_or(
                    InvalidProgramBehaviorError::UndeclaredProgramDependency {
                        program_id: owner_id,
                    },
                )?
            };
            let update_receipt = owner_program.prove_update_from_diff(&pre.account, diff_data)?;
            let update_output: UpdateFromDiffOutput = update_receipt
                .journal
                .decode()
                .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;
            update_from_diff_results.push(update_output.data);
            env_builder.add_assumption(update_receipt);
        }

        // TODO: remove clone
        program_outputs.push(program_output.clone());

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in program_output.chained_calls.into_iter().rev() {
            let next_program = dependencies.get(&new_call.program_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    program_id: new_call.program_id,
                },
            )?;
            chained_calls.push_front((new_call, next_program, Some(chained_call.program_id)));
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
        update_from_diff_results,
        signer_account_ids,
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
    caller_program_id: Option<ProgramId>,
    pre_states: &[AccountWithMetadata],
    instruction_data: &InstructionData,
) -> Result<Receipt, LeeError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    Program::write_inputs(
        program.id(),
        caller_program_id,
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
