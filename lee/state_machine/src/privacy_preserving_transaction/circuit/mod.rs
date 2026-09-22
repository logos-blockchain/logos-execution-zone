use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, PrivateWitness,
    ProgramImageClaim, ProvenCall,
    account::{AccountId, ProgramShardSelector},
    execution_state::{ExecutionState, NoPublicFacts, PublicEffects, RootCall},
    from_frame,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{InstructionData, ResolveOutput},
    to_frame,
};
use risc0_zkvm::{
    ExecutorEnv, ExecutorEnvBuilder, InnerReceipt, ProverOpts, Receipt, default_prover,
};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
    error::{InvalidProgramBehaviorError, LeeError},
    program::{Program, planner_journal, resolver_journal},
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
    /// Where the top-level call is dispatched — never assumed to be the root bytecode's
    /// bijection address, since the same bytecode may be deployed more than once at different
    /// addresses.
    pub self_account_id: AccountId,
    // TODO: avoid having a copy of the bytecode of each program.
    /// Every program this execution may dispatch, root included, keyed by the account address
    /// it's deployed at — never its bytecode identity, for the same reason. The caller building
    /// this off-chain (e.g. the wallet) already knows which program lives where; there's no live
    /// state to look it up against inside a pure proving function.
    pub programs: HashMap<AccountId, Program>,
}

impl ProgramWithDependencies {
    #[must_use]
    pub fn new(
        program: Program,
        self_account_id: AccountId,
        dependencies: HashMap<AccountId, Program>,
    ) -> Self {
        let mut programs = dependencies;
        programs.insert(self_account_id, program);
        Self {
            self_account_id,
            programs,
        }
    }
}

impl ProgramWithDependencies {
    #[must_use]
    pub fn native() -> Self {
        Self {
            self_account_id: NATIVE_TOKEN_PROGRAM_ID,
            programs: HashMap::new(),
        }
    }
}

impl From<Program> for ProgramWithDependencies {
    /// Assumes `program` lives at its bijection address — the common case (genesis-seeded
    /// builtins, or anything not yet moved by `program_loader`). Use [`Self::new`] directly for a
    /// program deployed elsewhere.
    fn from(program: Program) -> Self {
        let self_account_id = AccountId::from(program.id());
        Self::new(program, self_account_id, HashMap::new())
    }
}

/// Inputs for proving an LEE program's execution.
///
/// Carries no public account contents: planning is state-free, and a public effect is recorded
/// for settlement rather than resolved here.
#[derive(Default)]
pub struct ProvingInput {
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub signers: HashSet<AccountId>,
    pub private_witnesses: Vec<PrivateWitness>,
    pub instruction_data: InstructionData,
    pub dummy_inputs: Vec<DummyInput>,
}

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
pub fn execute_and_prove(
    input: ProvingInput,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let ProvingInput {
        shard_selectors,
        signers,
        private_witnesses,
        instruction_data,
        dummy_inputs,
    } = input;
    let ProgramWithDependencies {
        self_account_id: initial_account_id,
        programs,
    } = program_with_dependencies;

    let root = RootCall {
        program_account_id: *initial_account_id,
        shard_selectors,
        instruction_data,
        authorized_accounts: signers.into_iter().collect(),
    };
    let mut source = NoPublicFacts;
    let mut state =
        ExecutionState::initialize(root.clone(), &private_witnesses, PublicEffects::Defer)?;

    let mut env_builder = ExecutorEnv::builder();
    let mut calls = Vec::new();
    while let Some(call) = state.prepare_next_call()? {
        let self_account_id = call.self_account_id;
        // The native token program is recomputed by the circuit from the protocol's own
        // implementation, so it has neither an ELF to prove nor a receipt to carry.
        let (plan, program) = if self_account_id == NATIVE_TOKEN_PROGRAM_ID {
            let plan =
                native_token::execute(call.caller_account_id, &call.accounts, &call.instruction)
                    .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?;
            (plan, None)
        } else {
            let program = programs.get(&self_account_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    program_account_id: self_account_id,
                },
            )?;
            let receipt = prove_session(program, |env| Program::write_execute_inputs(call, env))?;
            let plan = planner_journal(&receipt.journal.bytes)?;
            env_builder.add_assumption(receipt);
            (plan, Some(program))
        };

        state.bind_plan(plan.clone())?;

        let mut private_resolutions = Vec::new();
        while let Some(obligation) = state.next_obligation(&mut source)? {
            let scheduled = obligation.clone();
            let resolution = match program {
                None => ResolveOutput {
                    post_data: Some(
                        native_token::resolve(&scheduled)
                            .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?,
                    ),
                    input: scheduled,
                },
                Some(program) => {
                    let receipt = prove_session(program, |env| {
                        Program::write_resolve_inputs(&scheduled, env)
                    })?;
                    let resolution = resolver_journal(&receipt.journal.bytes)?;
                    env_builder.add_assumption(receipt);
                    private_resolutions.push(resolution.clone());
                    resolution
                }
            };
            state.accept_resolution(&resolution)?;
        }
        state.complete_call()?;
        calls.push(ProvenCall {
            plan,
            private_resolutions,
        });
    }

    // Every address-deployed program actually invoked, claimed against its real bytecode
    // identity — the guest circuit uses these for `env::verify`, unchecked; the sequencer
    // verifies each one against real chain state before accepting the proof (see
    // `ProgramImageClaim`'s doc comment).
    let program_image_claims: Vec<ProgramImageClaim> = programs
        .iter()
        .map(|(account_id, program)| ProgramImageClaim {
            account_id: *account_id,
            image_id: program.id(),
        })
        .collect();

    let circuit_input = PrivacyPreservingCircuitInput {
        root,
        private_witnesses,
        dummy_inputs,
        program_image_claims,
        calls,
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

    let circuit_output: PrivacyPreservingCircuitOutput = borsh::from_slice(
        from_frame(&prove_info.receipt.journal.bytes).ok_or_else(|| {
            LeeError::CircuitOutputDeserializationError(
                "malformed circuit journal frame".to_owned(),
            )
        })?,
    )
    .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((circuit_output, proof))
}

fn prove_session(
    program: &Program,
    write: impl FnOnce(&mut ExecutorEnvBuilder) -> Result<(), LeeError>,
) -> Result<Receipt, LeeError> {
    let mut env_builder = ExecutorEnv::builder();
    write(&mut env_builder)?;
    let env = env_builder.build().unwrap();

    Ok(default_prover()
        .prove(env, program.elf())
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests;
