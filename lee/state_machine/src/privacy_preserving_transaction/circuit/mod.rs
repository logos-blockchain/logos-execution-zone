use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, PrivateWitness,
    ProgramImageClaim,
    account::{Account, AccountId, ProgramShardSelector, ShardData},
    execution_state::{ExecutionState, InstructionEcho, PublicSource, RootCall},
    from_frame,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{CallKind, InstructionData, ProgramInput, ProgramOutput},
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
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
#[derive(Default)]
pub struct ProvingInput {
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub signers: HashSet<AccountId>,
    pub public_accounts: HashMap<AccountId, Account>,
    pub private_witnesses: Vec<PrivateWitness>,
    pub instruction_data: InstructionData,
    pub dummy_inputs: Vec<DummyInput>,
}

struct LocalSource<'accounts> {
    signers: &'accounts HashSet<AccountId>,
    public_accounts: &'accounts HashMap<AccountId, Account>,
    root_shard_selectors: HashSet<ProgramShardSelector>,
    resolve: &'accounts mut dyn FnMut(ProgramShardSelector) -> Result<Option<ShardData>, LeeError>,
}

impl PublicSource for LocalSource<'_> {
    type Error = LeeError;

    fn account(&mut self, account_id: AccountId) -> Result<bool, LeeError> {
        Ok(self.signers.contains(&account_id))
    }

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, LeeError> {
        let shard_selector = ProgramShardSelector::new(account_id, program_account_id);
        let resolved = if self.root_shard_selectors.contains(&shard_selector) {
            None
        } else {
            (self.resolve)(shard_selector)?
        };
        Ok(resolved.unwrap_or_else(|| {
            self.public_accounts
                .get(&account_id)
                .map_or_else(ShardData::empty, |account| {
                    account.data.shard(program_account_id).clone()
                })
        }))
    }
}

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
pub fn execute_and_prove(
    input: ProvingInput,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    execute_and_prove_with(input, program_with_dependencies, &mut |_| Ok(None))
}

/// Like [`execute_and_prove`], with `resolve` for additional public shards used by chained calls.
/// `resolve` is called at most once per selector; `None` keeps the local value.
pub fn execute_and_prove_with(
    input: ProvingInput,
    program_with_dependencies: &ProgramWithDependencies,
    resolve: &mut dyn FnMut(ProgramShardSelector) -> Result<Option<ShardData>, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let ProvingInput {
        shard_selectors,
        signers,
        public_accounts,
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
    };
    let mut source = LocalSource {
        signers: &signers,
        public_accounts: &public_accounts,
        root_shard_selectors: root.shard_selectors.iter().copied().collect(),
        resolve,
    };
    let mut state = ExecutionState::initialize(
        root.clone(),
        CallKind::Execute,
        &private_witnesses,
        &mut source,
    )?;

    let mut env_builder = ExecutorEnv::builder();
    let mut effects = Vec::new();
    while let Some(call) = state.prepare_next_call(&mut source)? {
        let (output, receipt) = if call.self_account_id == NATIVE_TOKEN_PROGRAM_ID {
            let output =
                native_token::execute(call.caller_account_id, &call.pre_states, &call.instruction)
                    .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?;
            (output, None)
        } else {
            let program = programs.get(&call.self_account_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    program_account_id: call.self_account_id,
                },
            )?;
            let receipt = execute_and_prove_program(program, call)?;
            let output: ProgramOutput =
                borsh::from_slice(from_frame(&receipt.journal.bytes).ok_or_else(|| {
                    LeeError::ProgramOutputDeserializationError(
                        "malformed inner-receipt journal frame".to_owned(),
                    )
                })?)
                .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;
            (output, Some(receipt))
        };

        let call_effects = state.bind_output(output, InstructionEcho::Checked)?;
        effects.push(call_effects.clone());
        state.complete_call(call_effects, |_| {})?;
        if let Some(receipt) = receipt {
            env_builder.add_assumption(receipt);
        }
    }
    let root_call_kind = state.root_call_kind();
    let public_facts = state
        .finish()?
        .public_actions
        .into_iter()
        .map(|action| (action.account_id, (action.is_authorized, action.pre)))
        .collect();

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
        root_call_kind,
        public_facts,
        private_witnesses,
        dummy_inputs,
        program_image_claims,
        effects,
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

fn execute_and_prove_program(
    program: &Program,
    input: &ProgramInput<InstructionData>,
) -> Result<Receipt, LeeError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    Program::write_inputs(input, &mut env_builder)?;
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
