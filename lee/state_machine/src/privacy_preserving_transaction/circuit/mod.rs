use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, MembershipProof, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput,
    PrivateWitness, ProgramImageWitness, ProvenCall, ShadowProgramWitness,
    account::{AccountId, ProgramShardSelector},
    execution_state::{Backend, DeferPublicEffects, ExecutionState, RootCall},
    from_frame,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        ApplyInput, ApplyOutput, InstructionData, PlanInput, PlanOutput, ProgramEvent,
        ProgramHeader,
    },
    to_frame,
};
use risc0_zkvm::{
    ExecutorEnv, ExecutorEnvBuilder, InnerReceipt, ProverOpts, Receipt, default_prover,
};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
    error::{InvalidProgramBehaviorError, LeeError},
    program::{Program, apply_journal, check_exit_code, plan_journal},
};

/// Proof of the privacy preserving execution circuit.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proof(pub(crate) Vec<u8>);

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[proof redacted for brevity ({} bytes)]", self.0.len())
    }
}

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
pub enum ProgramKind {
    /// Publicly disclosed.
    Disclosed,
    /// Never deployed to LEZ's public state.
    Shadow,
    /// An immutable program executed without disclosing which one it is.
    Undisclosed {
        program_header: ProgramHeader,
        membership_proof: MembershipProof,
    },
}

#[derive(Clone)]
pub struct Dependency {
    pub program: Program,
    pub kind: ProgramKind,
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
    pub programs: HashMap<AccountId, Dependency>,
}

impl ProgramWithDependencies {
    #[must_use]
    pub fn new(
        program: Program,
        self_account_id: AccountId,
        dependencies: HashMap<AccountId, Program>,
    ) -> Self {
        let programs = dependencies
            .into_iter()
            .chain([(self_account_id, program)])
            .map(|(account_id, dep_program)| {
                (
                    account_id,
                    Dependency {
                        program: dep_program,
                        kind: ProgramKind::Disclosed,
                    },
                )
            })
            .collect();
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

    /// Marks the root program as a shadow program: dispatched at
    /// `AccountId::for_shadow_program(program.id())`, resolved via a fresh
    /// [`ShadowProgramWitness`] instead of a public claim.
    #[must_use]
    pub fn as_shadow_program(mut self) -> Self {
        if let Some(root) = self.programs.remove(&self.self_account_id) {
            self.self_account_id = AccountId::for_shadow_program(&root.program.id());
            self.programs.insert(
                self.self_account_id,
                Dependency {
                    kind: ProgramKind::Shadow,
                    ..root
                },
            );
        }
        self
    }

    #[must_use]
    pub fn with_shadow_dependency(mut self, account_id: AccountId) -> Self {
        if let Some(dependency) = self.programs.get_mut(&account_id) {
            dependency.kind = ProgramKind::Shadow;
        }
        self
    }

    /// `ProgramImageClaim::Undisclosed` instead of `Disclosed`.
    #[must_use]
    pub fn as_undisclosed_program(
        self,
        program_header: ProgramHeader,
        membership_proof: MembershipProof,
    ) -> Self {
        let root = self.self_account_id;
        self.with_undisclosed_dependency(root, program_header, membership_proof)
    }

    #[must_use]
    pub fn with_undisclosed_dependency(
        mut self,
        account_id: AccountId,
        program_header: ProgramHeader,
        membership_proof: MembershipProof,
    ) -> Self {
        if let Some(dependency) = self.programs.get_mut(&account_id) {
            dependency.kind = ProgramKind::Undisclosed {
                program_header,
                membership_proof,
            };
        }
        self
    }
}

/// Inputs for proving an LEE program's execution.
#[derive(Default)]
pub struct ProvingInput {
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub signers: HashSet<AccountId>,
    pub private_witnesses: Vec<PrivateWitness>,
    pub instruction_data: InstructionData,
    pub dummy_inputs: Vec<DummyInput>,
    /// Minimum length each emitted note is padded to, so notes do not leak their
    /// account's size. `None` leaves them at their natural length.
    pub ciphertext_padding: Option<u32>,
}

struct Prover<'programs> {
    programs: &'programs HashMap<AccountId, Dependency>,
    env_builder: ExecutorEnvBuilder<'static>,
    calls: Vec<ProvenCall>,
}

impl<'programs> Backend for Prover<'programs> {
    type Call = Option<(&'programs Program, ProvenCall)>;
    type Error = LeeError;
    type PublicEffects = DeferPublicEffects;

    fn plan(
        &mut self,
        input: &PlanInput,
        _execution: &ExecutionState<'_>,
    ) -> Result<(PlanOutput, Self::Call), LeeError> {
        let self_account_id = input.self_account_id;
        // The native token program is recomputed by the circuit from the protocol's own
        // implementation, so it has neither an ELF to prove nor a transcript to carry.
        if self_account_id == NATIVE_TOKEN_PROGRAM_ID {
            let plan = native_token::plan(
                input.caller_account_id,
                &input.accounts,
                &input.instruction_data,
            )
            .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?;
            return Ok((plan, None));
        }
        let program = &self
            .programs
            .get(&self_account_id)
            .ok_or(InvalidProgramBehaviorError::UndeclaredProgramDependency {
                program_account_id: self_account_id,
            })?
            .program;
        let receipt = prove_session(program, |env| Program::write_plan_inputs(input, env))?;
        let plan = plan_journal(&receipt.journal.bytes)?;
        self.env_builder.add_assumption(receipt);
        let proven = ProvenCall {
            plan: plan.clone(),
            private_apply_outputs: Vec::new(),
        };
        Ok((plan, Some((program, proven))))
    }

    fn apply(
        &mut self,
        call: &mut Self::Call,
        input: &ApplyInput,
    ) -> Result<ApplyOutput, LeeError> {
        let Some((program, proven)) = call else {
            return Ok(native_token::apply_output(input)
                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?);
        };
        let receipt = prove_session(program, |env| Program::write_apply_inputs(input, env))?;
        let output = apply_journal(&receipt.journal.bytes)?;
        self.env_builder.add_assumption(receipt);
        proven.private_apply_outputs.push(output.clone());
        Ok(output)
    }

    fn complete(
        &mut self,
        call: Self::Call,
        _events: Vec<ProgramEvent>,
        _execution: &ExecutionState<'_>,
    ) -> Result<(), LeeError> {
        self.calls.extend(call.map(|(_, proven)| proven));
        Ok(())
    }
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
        ciphertext_padding,
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
    let mut backend = Prover {
        programs,
        env_builder: ExecutorEnv::builder(),
        calls: Vec::new(),
    };
    ExecutionState::initialize(root.clone(), &private_witnesses)?.run(&mut backend)?;
    let Prover {
        mut env_builder,
        calls,
        ..
    } = backend;

    // Every program actually invoked, claimed against its real bytecode identity — the guest
    // circuit uses these for `env::verify`, unchecked; the sequencer verifies each `Disclosed` one
    // against real chain state before accepting the proof, while `Undisclosed` is checked
    // in-circuit — unless it's resolved as shadow instead.
    let mut program_image_witnesses = Vec::new();
    let mut shadow_program_witnesses = Vec::new();
    #[expect(
        clippy::iter_over_hash_type,
        reason = "Witness order is not significant; the journal echoes whatever order is supplied"
    )]
    for (account_id, Dependency { program, kind }) in programs {
        match kind {
            ProgramKind::Disclosed => {
                program_image_witnesses.push(ProgramImageWitness::Disclosed {
                    account_id: *account_id,
                    image_id: program.id(),
                });
            }
            ProgramKind::Undisclosed {
                program_header,
                membership_proof,
            } => program_image_witnesses.push(ProgramImageWitness::Undisclosed {
                account_id: *account_id,
                program_header: *program_header,
                membership_proof: membership_proof.clone(),
            }),
            ProgramKind::Shadow => shadow_program_witnesses.push(ShadowProgramWitness {
                image_id: program.id(),
            }),
        }
    }

    let circuit_input = PrivacyPreservingCircuitInput {
        root,
        private_witnesses,
        dummy_inputs,
        ciphertext_padding,
        program_image_witnesses,
        shadow_program_witnesses,
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

    // Prove the program
    let prover = default_prover();
    let prove_info = prover
        .prove(env, program.elf())
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?;

    // The local prover proves any exit code, and the circuit's `env::verify` only resolves a
    // `Halted(0)` claim, so gate here for a typed error before the expensive circuit proof.
    let exit_code = prove_info
        .receipt
        .claim()
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .as_value()
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .exit_code;
    check_exit_code(
        exit_code,
        prove_info.stats.user_cycles,
        LeeError::ProgramProveFailed,
    )?;
    Ok(prove_info.receipt)
}

#[cfg(test)]
mod tests;
