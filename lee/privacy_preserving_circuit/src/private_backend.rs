//! The privacy preserving circuit's half of the shared traversal: it verifies a proof of
//! each call.

use std::{collections::HashMap, convert::Infallible, vec};

use lee_core::{
    ProvenCall,
    account::AccountId,
    execution_state::{Backend, DeferPublicEffects, ExecutionError, ExecutionState},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        ApplyInput, ApplyOutput, GuestOutput, PROGRAM_LOADER_ACCOUNT_ID, PlanInput, PlanOutput,
        ProgramEvent, ProgramId,
    },
};
use risc0_zkvm::guest::env;

pub struct PrivateBackend {
    image_ids: HashMap<AccountId, ProgramId>,
    transcript: vec::IntoIter<ProvenCall>,
}

impl PrivateBackend {
    pub fn new(image_ids: HashMap<AccountId, ProgramId>, calls: Vec<ProvenCall>) -> Self {
        Self {
            image_ids,
            transcript: calls.into_iter(),
        }
    }

    pub fn finish(mut self) {
        assert!(
            self.transcript.next().is_none(),
            "A call transcript was supplied for a call nothing scheduled"
        );
    }
}

impl Backend for PrivateBackend {
    type Call = Option<(ProgramId, vec::IntoIter<ApplyOutput>)>;
    type Error = ExecutionError;
    type PublicEffects = DeferPublicEffects;

    fn plan(
        &mut self,
        input: &PlanInput,
        _execution: &ExecutionState<'_>,
    ) -> Result<(PlanOutput, Self::Call), ExecutionError> {
        assert_ne!(
            input.self_account_id, PROGRAM_LOADER_ACCOUNT_ID,
            "The program loader is a public-only native operation and cannot be proven"
        );
        // The native token program has no ELF to verify against, so its plan is recomputed
        // here rather than taken from the prover.
        if input.self_account_id == NATIVE_TOKEN_PROGRAM_ID {
            let plan = native_token::plan(
                input.caller_account_id,
                &input.accounts,
                &input.instruction_data,
            )
            .unwrap_or_else(|e| panic!("{e}"));
            return Ok((plan, None));
        }
        let ProvenCall {
            plan,
            private_apply_outputs,
        } = self
            .transcript
            .next()
            .expect("a scheduled call must carry its call transcript");
        // One image id per invocation, used for that invocation's plan and for every apply it
        // schedules: an apply is verified under the same program that planned it.
        let image_id = *self
            .image_ids
            .get(&input.self_account_id)
            .expect("no image_id claim supplied for invoked program account");
        Ok((
            verified_plan(image_id, plan),
            Some((image_id, private_apply_outputs.into_iter())),
        ))
    }

    fn apply(
        &mut self,
        call: &mut Self::Call,
        input: &ApplyInput,
    ) -> Result<ApplyOutput, ExecutionError> {
        Ok(match call {
            None => native_token::apply_output(input).unwrap_or_else(|e| panic!("{e}")),
            Some((image_id, outputs)) => verified_apply_output(
                *image_id,
                outputs
                    .next()
                    .expect("a private effect must carry its apply output"),
            ),
        })
    }

    fn complete(
        &mut self,
        call: Self::Call,
        _events: Vec<ProgramEvent>,
        _execution: &ExecutionState<'_>,
    ) -> Result<(), ExecutionError> {
        if let Some((_, mut outputs)) = call {
            assert!(
                outputs.next().is_none(),
                "A call supplied more apply outputs than it emitted private effects"
            );
        }
        Ok(())
    }
}

/// The journal is the tagged `GuestOutput`, so an apply receipt can never satisfy a plan
/// slot: it commits different bytes under a different tag.
fn verified_plan(image_id: ProgramId, plan: PlanOutput) -> PlanOutput {
    let journal = GuestOutput::Plan(plan);
    verify(image_id, &journal);
    let GuestOutput::Plan(verified) = journal else {
        unreachable!("the journal was just constructed as a plan")
    };
    verified
}

fn verified_apply_output(image_id: ProgramId, output: ApplyOutput) -> ApplyOutput {
    let journal = GuestOutput::Apply(output);
    verify(image_id, &journal);
    let GuestOutput::Apply(verified) = journal else {
        unreachable!("the journal was just constructed as an apply output")
    };
    verified
}

fn verify(image_id: ProgramId, journal: &GuestOutput) {
    env::verify(image_id, &lee_core::to_borsh_frame(journal))
        .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
}
