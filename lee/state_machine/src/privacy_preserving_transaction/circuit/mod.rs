use std::collections::{BTreeSet, HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    MembershipProof, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput,
    ProgramImageWitness, ProvenExecution, ProvingInput, RecipientEncryption, SenderPresentation,
    ShadowProgramWitness,
    account::{AccountId, Actor, ActorState, Cycles},
    execution_state::{
        ExecutionEnvironment, ExecutionError, Placement, PredictedCrossMessages, PrivatePart,
        PublicExecutionContext, TransitionView, WholeTransaction,
    },
    from_frame,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, ProgramHeader, ReceiveInput, Response, Transition},
    to_frame,
};
use risc0_zkvm::{
    ExecutorEnv, ExecutorEnvBuilder, InnerReceipt, ProverOpts, Receipt, default_prover,
};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
    error::{InvalidProgramBehaviorError, LeeError},
    program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program, check_exit_code, transition_journal},
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

    pub(crate) fn is_valid_for(
        &self,
        context: &PublicExecutionContext,
        execution: &ProvenExecution,
    ) -> bool {
        let Ok(inner) = borsh::from_slice::<InnerReceipt>(&self.0) else {
            return false;
        };
        let receipt = Receipt::new(inner, lee_core::to_borsh_frame(&(context, execution)));
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

#[derive(Clone, Default)]
pub struct ProgramCatalog {
    // TODO: avoid having a copy of the bytecode of each program.
    /// Every program this execution may dispatch, keyed by the account address it's deployed at
    /// — never its bytecode identity, since the same bytecode may be deployed more than once at
    /// different addresses. The caller building this off-chain (e.g. the wallet) already knows
    /// which program lives where; there's no live state to look it up against inside a pure
    /// proving function.
    pub programs: HashMap<AccountId, Dependency>,
}

impl FromIterator<(AccountId, Program)> for ProgramCatalog {
    fn from_iter<I: IntoIterator<Item = (AccountId, Program)>>(iter: I) -> Self {
        Self {
            programs: iter
                .into_iter()
                .map(|(account_id, program)| {
                    (
                        account_id,
                        Dependency {
                            program,
                            kind: ProgramKind::Disclosed,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl<const N: usize> From<[(AccountId, Program); N]> for ProgramCatalog {
    fn from(entries: [(AccountId, Program); N]) -> Self {
        entries.into_iter().collect()
    }
}

impl ProgramCatalog {
    /// Resolves the program at `account_id`, which must be
    /// `AccountId::for_shadow_program(&program.id())`, via a fresh [`ShadowProgramWitness`]
    /// instead of a public claim.
    #[must_use]
    pub fn with_shadow(mut self, account_id: AccountId) -> Self {
        if let Some(dependency) = self.programs.get_mut(&account_id) {
            dependency.kind = ProgramKind::Shadow;
        }
        self
    }

    /// `ProgramImageClaim::Undisclosed` instead of `Disclosed`.
    #[must_use]
    pub fn with_undisclosed(
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

/// Public states assumed for simulation purposes of a private part of a transaction.
#[derive(Default)]
pub struct Simulation {
    pub public_actor_states: HashMap<Actor, ActorState>,
    /// The public accounts settlement admits, or `None` to admit every one.
    pub admitted_accounts: Option<BTreeSet<AccountId>>,
}

/// A recorder deriving the presentations of private senders.
struct SenderPresentationRecorder<'present> {
    choose: &'present mut dyn FnMut(Actor) -> Option<SenderPresentation>,
    recorded: Vec<SenderPresentation>,
}

impl SenderPresentationRecorder<'_> {
    fn present(&mut self, sender: Actor) -> Result<SenderPresentation, LeeError> {
        let presentation =
            (self.choose)(sender).ok_or(ExecutionError::MissingSenderPresentation { sender })?;
        self.recorded.push(presentation);
        Ok(presentation)
    }
}

/// A selector of which asynchronous messages will be delivered atomically.
struct CastPromotionSelector<'select> {
    select: &'select mut dyn FnMut(Placement, &MessageBody) -> bool,
    from_public: PromotionSelection,
    from_private: PromotionSelection,
}

/// The selection of casts to be delivered atomically and which are left.
struct PromotionSelection {
    remaining_requested: BTreeSet<u64>,
    selected: BTreeSet<u64>,
}

impl PromotionSelection {
    const fn new(requested: BTreeSet<u64>) -> Self {
        Self {
            remaining_requested: requested,
            selected: BTreeSet::new(),
        }
    }

    fn finish(self) -> Result<BTreeSet<u64>, LeeError> {
        match self.remaining_requested.first() {
            Some(&index) => Err(ExecutionError::UnreachedCastPromotion { index }.into()),
            None => Ok(self.selected),
        }
    }
}

/// A simulator recording the data for private execution by running thins in plaintext.
struct Simulator<'input> {
    programs: &'input HashMap<AccountId, Dependency>,
    public_actor_states: &'input HashMap<Actor, ActorState>,
    admitted_accounts: Option<&'input BTreeSet<AccountId>>,
    recorder: SenderPresentationRecorder<'input>,
    selector: CastPromotionSelector<'input>,
    cycle_budget: Cycles,
    cycles_used: Cycles,
}

impl ExecutionEnvironment for Simulator<'_> {
    type Error = LeeError;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        view: &TransitionView<'_>,
    ) -> Result<Transition, LeeError> {
        // A private transition is bounded only by what its prover can prove, as when it is proven.
        let runs_privately = view.runs_privately(input.receiver.account_id);
        handle_message_with(self.programs, input, |program| {
            if runs_privately {
                Ok(program.handle_message(input, Cycles::MAX)?.0)
            } else {
                program.handle_message_metered(input, self.cycle_budget, &mut self.cycles_used)
            }
        })
    }

    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, LeeError> {
        Ok(self
            .public_actor_states
            .get(&actor)
            .map_or_else(ActorState::empty, Clone::clone))
    }

    fn present(&mut self, sender: Actor) -> Result<SenderPresentation, LeeError> {
        self.recorder.present(sender)
    }

    fn admits(&mut self, account_id: AccountId) -> Result<bool, LeeError> {
        Ok(self
            .admitted_accounts
            .is_none_or(|admitted| admitted.contains(&account_id)))
    }

    fn promote(
        &mut self,
        placement: Placement,
        index: u64,
        body: &MessageBody,
    ) -> Result<bool, LeeError> {
        let CastPromotionSelector {
            select,
            from_public,
            from_private,
        } = &mut self.selector;
        let selection = match placement {
            Placement::Public => from_public,
            Placement::Private => from_private,
        };
        let selected = selection.remaining_requested.remove(&index) || select(placement, body);
        if selected {
            selection.selected.insert(index);
        }
        Ok(selected)
    }
}

/// The prover handling the generation of the proof of a private part of a transaction.
struct Prover<'programs> {
    programs: &'programs HashMap<AccountId, Dependency>,
    env_builder: ExecutorEnvBuilder<'static>,
    responses: Vec<Response>,
    invoked: BTreeSet<AccountId>,
    recorder: SenderPresentationRecorder<'programs>,
    select: &'programs mut dyn FnMut(u64, &MessageBody) -> bool,
    cast_promotions: BTreeSet<u64>,
}

impl ExecutionEnvironment for Prover<'_> {
    type Error = LeeError;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        _view: &TransitionView<'_>,
    ) -> Result<Transition, LeeError> {
        handle_message_with(self.programs, input, |program| {
            let receipt = prove_session(program, |env| Program::write_receive_input(input, env))?;
            let transition = transition_journal(&receipt.journal.bytes)?;
            self.env_builder.add_assumption(receipt);
            self.responses.push(transition.response.clone());
            self.invoked.insert(input.receiver.program_account_id);
            Ok(transition)
        })
    }

    fn present(&mut self, sender: Actor) -> Result<SenderPresentation, LeeError> {
        self.recorder.present(sender)
    }

    fn promote(
        &mut self,
        placement: Placement,
        index: u64,
        body: &MessageBody,
    ) -> Result<bool, LeeError> {
        let selected = placement == Placement::Private && (self.select)(index, body);
        if selected {
            self.cast_promotions.insert(index);
        }
        Ok(selected)
    }
}

fn handle_message_with(
    programs: &HashMap<AccountId, Dependency>,
    input: &ReceiveInput,
    run: impl FnOnce(&Program) -> Result<Transition, LeeError>,
) -> Result<Transition, LeeError> {
    let program_account_id = input.receiver.program_account_id;
    // The native token program is recomputed by the circuit from the protocol's own
    // implementation, so it has neither an ELF to prove nor a transition to carry.
    if program_account_id == NATIVE_TOKEN_PROGRAM_ID {
        return Ok(native_token::handle_message(input)
            .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?);
    }
    run(&programs
        .get(&program_account_id)
        .ok_or(InvalidProgramBehaviorError::UndeclaredProgramDependency { program_account_id })?
        .program)
}

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
///
/// It assumes of public execution what running it against `simulation.public_actor_states`
/// delivers, and executes at once each Cast to an undeclared destination that `input` selects or
/// `select_promotion` accepts.
pub fn execute_and_prove(
    mut input: ProvingInput,
    simulation: &Simulation,
    programs: &ProgramCatalog,
    mut present_sender: impl FnMut(Actor) -> SenderPresentation,
    mut select_promotion: impl FnMut(Placement, &MessageBody) -> bool,
    mut choose_seal: impl FnMut(&MessageBody) -> Result<RecipientEncryption, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    // Build a simulator to generate the parameters to generate the proof with.
    let mut simulator = Simulator {
        programs: &programs.programs,
        public_actor_states: &simulation.public_actor_states,
        admitted_accounts: simulation.admitted_accounts.as_ref(),
        recorder: SenderPresentationRecorder {
            choose: &mut |sender| Some(present_sender(sender)),
            recorded: Vec::new(),
        },
        selector: CastPromotionSelector {
            select: &mut select_promotion,
            from_public: PromotionSelection::new(input.context.cast_promotions.clone()),
            from_private: PromotionSelection::new(input.private_cast_promotions.clone()),
        },
        cycle_budget: DEFAULT_PUBLIC_CYCLE_BUDGET,
        cycles_used: 0,
    };

    // Given the initial context and top level call, simulate a whole transaction and record
    // predicted public-private messages.
    let predicted_cross_messages = WholeTransaction::new(
        input.context.clone(),
        input.root.clone().map(|witness| witness.body),
        &input.private_witnesses,
    )?
    .execute(&mut simulator)?
    .predicted_cross_messages;
    let Simulator {
        recorder, selector, ..
    } = simulator;
    input.context.cast_promotions = selector.from_public.finish()?;
    input.private_cast_promotions = selector.from_private.finish()?;
    let recorded = input.private_cast_promotions.clone();
    let mut presented = recorder.recorded.into_iter();
    // Given the simulated outputs, use them to prove the private part of the transaction.
    prove(
        input,
        predicted_cross_messages,
        programs,
        &mut |_| presented.next(),
        &mut |index, _| recorded.contains(&index),
        &mut choose_seal,
    )
}

/// Like [`execute_and_prove`], but under the given predicted cross messages and the promotions
/// `input` selects, with any further private Casts `select_promotion` chooses.
///
/// Settlement matches them against live public execution; a prover that did not derive them may
/// produce a proof settlement refuses.
pub fn execute_and_prove_with_cross_messages(
    input: ProvingInput,
    predicted_cross_messages: PredictedCrossMessages,
    programs: &ProgramCatalog,
    mut present_sender: impl FnMut(Actor) -> SenderPresentation,
    mut select_promotion: impl FnMut(Placement, &MessageBody) -> bool,
    mut choose_seal: impl FnMut(&MessageBody) -> Result<RecipientEncryption, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let requested = input.private_cast_promotions.clone();
    prove(
        input,
        predicted_cross_messages,
        programs,
        &mut |sender| Some(present_sender(sender)),
        &mut |index, body| requested.contains(&index) || select_promotion(Placement::Private, body),
        &mut choose_seal,
    )
}

fn prove(
    mut input: ProvingInput,
    predicted_cross_messages: PredictedCrossMessages,
    programs: &ProgramCatalog,
    choose: &mut dyn FnMut(Actor) -> Option<SenderPresentation>,
    select: &mut dyn FnMut(u64, &MessageBody) -> bool,
    choose_seal: &mut dyn FnMut(&MessageBody) -> Result<RecipientEncryption, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let ProgramCatalog { programs } = programs;

    let mut backend = Prover {
        programs,
        env_builder: ExecutorEnv::builder(),
        responses: Vec::new(),
        invoked: BTreeSet::new(),
        recorder: SenderPresentationRecorder {
            choose,
            recorded: Vec::new(),
        },
        select,
        cast_promotions: BTreeSet::new(),
    };
    let outcome = PrivatePart::new(
        input.context.clone(),
        input.root.clone().map(|witness| witness.body),
        &input.private_witnesses,
        predicted_cross_messages.clone(),
    )?
    .execute(&mut backend)?;
    if let Some(&index) = input
        .private_cast_promotions
        .difference(&backend.cast_promotions)
        .next()
    {
        return Err(ExecutionError::UnreachedCastPromotion { index }.into());
    }
    let cast_seals = outcome
        .casts
        .iter()
        .map(choose_seal)
        .collect::<Result<_, _>>()?;
    let Prover {
        mut env_builder,
        responses,
        invoked,
        recorder,
        cast_promotions,
        ..
    } = backend;
    input.private_cast_promotions = cast_promotions;

    // Every program actually invoked, claimed against its real bytecode identity — the guest
    // circuit uses these for `env::verify`, unchecked; the sequencer verifies each `Disclosed` one
    // against real chain state before accepting the proof, while `Undisclosed` is checked
    // in-circuit — unless it's resolved as shadow instead.
    let mut program_image_witnesses = Vec::new();
    let mut shadow_program_witnesses = Vec::new();
    for account_id in &invoked {
        let Dependency { program, kind } = &programs[account_id];
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
        input,
        program_image_witnesses,
        shadow_program_witnesses,
        responses,
        sender_presentations: recorder.recorded,
        cast_seals,
        predicted_cross_messages,
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
