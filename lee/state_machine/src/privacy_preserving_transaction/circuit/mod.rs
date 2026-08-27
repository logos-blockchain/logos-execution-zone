use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, InputAccount, InputAccountIdentity, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput,
    account::{AccountId, AccountWithMetadata},
    execution_state::{ExecutionState, index_by_account_id},
    parse_journal,
    program::{
        EntryCall, InstructionData, MAX_NUMBER_CHAINED_CALLS, ProgramEffects, ProgramId,
        ProgramOutput,
    },
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
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
///
/// `account_identities[i]` describes `pre_states[i]`. The circuit keys these by `AccountId`, so
/// this is the caller's own order throughout — not the order the entry program happens to commit
/// its `pre_states` in, which the caller cannot know before it runs.
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

/// As [`execute_and_prove`], with dummy private inputs padding the output. `account_identities[i]`
/// describes `pre_states[i]`.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Public entry point — taking ownership signals the caller hands off its top-level \
              account values for the duration of the proof; callers already construct these \
              freshly per call, so a borrow would just push the clone to every call site"
)]
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

    // `zip` below would silently drop a surplus identity, where the circuit's own count check
    // rejects it. Too few still reaches that check as an unresolvable account.
    ensure!(
        account_identities.len() <= pre_states.len(),
        LeeError::InvalidInput("More account identities than accounts".into())
    );

    // An account first sighted at depth was untouched until then — reaching it is what lets a
    // program modify it — so its top-level value is still its first-sight value, and the circuit
    // can be handed all of them up front.
    let build_input_accounts = || -> Vec<InputAccount> {
        pre_states
            .iter()
            .zip(account_identities.iter().cloned())
            .map(|(pre, identity)| InputAccount {
                account_id: pre.account_id,
                account: pre.account.clone(),
                is_authorized: pre.is_authorized,
                identity,
            })
            .collect()
    };
    let indexed_input_accounts = index_by_account_id(build_input_accounts())
        .map_err(|e| LeeError::InvalidInput(e.to_string()))?;

    let top_level_program_id = initial_program.id();
    let mut env_builder = ExecutorEnv::builder();

    // The entry call is proven on the caller's own accounts: no caller named them and no seeds
    // delegate them, so there is nothing to resolve. The order it commits them in is the order
    // the walk takes.
    let entry_receipt =
        execute_and_prove_program(initial_program, None, &pre_states, &instruction_data)?;
    let entry_output: ProgramOutput = parse_journal(&entry_receipt.journal.bytes)
        .map_err(LeeError::ProgramOutputDeserializationError)?;
    let top_level_accounts: Vec<AccountId> = entry_output
        .pre_states
        .iter()
        .map(|pre| pre.account_id)
        .collect();
    env_builder.add_assumption(entry_receipt);

    let mut program_effects: Vec<ProgramEffects> = Vec::new();
    let mut entry_output = Some(entry_output);
    // The host has always rejected one call earlier than the circuit's own cap does, and keeps
    // doing so: the tally is spent before anything is proven.
    let mut invocations = 0;

    // The host runs the circuit's own walk, so what it feeds each program is what the circuit
    // will re-derive and verify the journal against.
    let top_level_call = EntryCall {
        program_id: top_level_program_id,
        instruction_data,
        accounts: top_level_accounts,
    };

    ExecutionState::derive(
        &indexed_input_accounts,
        top_level_call.clone(),
        |call, derived_pre_states| -> Result<ProgramOutput, LeeError> {
            if invocations >= MAX_NUMBER_CHAINED_CALLS {
                return Err(LeeError::MaxChainedCallsDepthExceeded);
            }
            invocations = invocations
                .checked_add(1)
                .expect("the tally is bounded by the depth cap checked just above");

            let output = if let Some(entry_output) = entry_output.take() {
                entry_output
            } else {
                let program = dependencies.get(&call.self_program_id).ok_or(
                    InvalidProgramBehaviorError::UndeclaredProgramDependency {
                        program_id: call.self_program_id,
                    },
                )?;
                let receipt = execute_and_prove_program(
                    program,
                    call.caller_program_id,
                    &derived_pre_states,
                    &call.instruction_data,
                )?;
                let output: ProgramOutput = parse_journal(&receipt.journal.bytes)
                    .map_err(LeeError::ProgramOutputDeserializationError)?;
                env_builder.add_assumption(receipt);
                output
            };

            // The circuit verifies every receipt against a journal it rebuilds from this same
            // derivation, so a journal that disagrees here can never discharge its assumption.
            // Failing now costs one program proof instead of the whole circuit proof.
            ensure!(
                output.pre_states == derived_pre_states,
                InvalidProgramBehaviorError::JournalledPreStatesMismatch {
                    program_id: call.self_program_id
                }
            );

            program_effects.push(output.effects.clone());
            Ok(output)
        },
    )?;

    let circuit_input = PrivacyPreservingCircuitInput {
        program_effects,
        top_level_call,
        input_accounts: build_input_accounts(),
        dummy_inputs,
    };

    let circuit_input_payload = borsh::to_vec(&circuit_input)?;
    env_builder.write_slice(&to_frame(&circuit_input_payload));
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &opts)
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);

    let circuit_output: PrivacyPreservingCircuitOutput =
        parse_journal(&prove_info.receipt.journal.bytes)
            .map_err(LeeError::CircuitOutputDeserializationError)?;

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
    program.write_inputs(
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
