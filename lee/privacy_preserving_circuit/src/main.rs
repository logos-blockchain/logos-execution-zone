use std::{collections::HashMap, convert::Infallible};

use lee_core::{
    PrivacyPreservingCircuitInput, ProvenCall,
    account::AccountId,
    execution_state::{ExecutionState, NoPublicFacts, PublicEffects},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        GuestOutput, PROGRAM_LOADER_ACCOUNT_ID, ProgramId, ProgramOutput, ResolveOutput,
        read_input_frame,
    },
};
use risc0_zkvm::guest::env;

mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        root,
        private_witnesses,
        dummy_inputs,
        program_image_claims,
        calls,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    // Untrusted claims supplied by the prover: `env::verify` needs a real image id, not an
    // arbitrary dispatch address. The circuit does not check these against real chain state —
    // the sequencer does that independently (`V03State::get_program_image_id`) before
    // accepting the proof, which fails naturally if a claim is a lie (the receipt's actually
    // committed bytes won't match the reconstructed output). See `ProgramImageClaim`.
    // Neither reserved address is a deployed guest: native balance is recomputed below and the
    // loader is a public-only native operation. A claim naming either would let a prover supply
    // an ELF for an address the protocol implements itself.
    assert!(
        !program_image_claims.iter().any(|claim| {
            claim.account_id == NATIVE_TOKEN_PROGRAM_ID
                || claim.account_id == PROGRAM_LOADER_ACCOUNT_ID
        }),
        "A reserved program account has no deployable bytecode to claim"
    );

    let image_id_by_account_id: HashMap<AccountId, ProgramId> = program_image_claims
        .iter()
        .map(|claim| (claim.account_id, claim.image_id))
        .collect();

    let mut source = NoPublicFacts;
    let mut state = ExecutionState::initialize(root, &private_witnesses, PublicEffects::Defer)
        .unwrap_or_else(|e| panic!("{e}"));

    for ProvenCall {
        plan,
        private_resolutions,
    } in calls
    {
        // One image id per invocation, used for that invocation's plan and for every resolver it
        // schedules: a resolver is verified under the same program that planned it.
        let (plan, image_id) = {
            let call = state
                .prepare_next_call()
                .unwrap_or_else(|e| panic!("{e}"))
                .expect("A call transcript was supplied for a call nothing scheduled");
            assert_ne!(
                call.self_account_id, PROGRAM_LOADER_ACCOUNT_ID,
                "The program loader is a public-only native operation and cannot be proven"
            );
            let image_id = (call.self_account_id != NATIVE_TOKEN_PROGRAM_ID).then(|| {
                *image_id_by_account_id
                    .get(&call.self_account_id)
                    .expect("no image_id claim supplied for invoked program account")
            });
            // The native token program has no ELF to verify against, so its plan is recomputed
            // here rather than taken from the prover.
            let plan = image_id.map_or_else(
                || {
                    native_token::execute(call.caller_account_id, &call.accounts, &call.instruction)
                        .unwrap_or_else(|e| panic!("{e}"))
                },
                |image_id| verified_plan(image_id, plan),
            );
            (plan, image_id)
        };
        state.bind_plan(plan).unwrap_or_else(|e| panic!("{e}"));

        let mut resolutions = private_resolutions.into_iter();
        while let Some(obligation) = state
            .next_obligation(&mut source)
            .unwrap_or_else(|e| panic!("{e}"))
        {
            let input = obligation.clone();
            let resolution = image_id.map_or_else(
                || ResolveOutput {
                    post_data: Some(
                        native_token::resolve(&input).unwrap_or_else(|e| panic!("{e}")),
                    ),
                    input: input.clone(),
                },
                |image_id| {
                    verified_resolution(
                        image_id,
                        resolutions
                            .next()
                            .expect("a private effect must carry its resolution"),
                    )
                },
            );
            // Every field of the resolution's echoed input is matched against the effect the
            // engine scheduled and the shard it holds now, so a verified receipt of the right
            // program still has to be the receipt of *this* obligation.
            state
                .accept_resolution(&resolution)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert!(
            resolutions.next().is_none(),
            "A call supplied more resolutions than it emitted private effects"
        );
        state.complete_call().unwrap_or_else(|e| panic!("{e}"));
    }

    // A call scheduled but left without a transcript is caught here: `finish` refuses to
    // complete with work still pending.
    let final_state = state.finish().unwrap_or_else(|e| panic!("{e}"));

    let output = output::compute_circuit_output(
        final_state,
        &private_witnesses,
        dummy_inputs,
        program_image_claims,
    );

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}

/// The journal is the tagged `GuestOutput`, so a resolver receipt can never satisfy a planner
/// slot: it commits different bytes under a different tag.
fn verified_plan(image_id: ProgramId, plan: ProgramOutput) -> ProgramOutput {
    let journal = GuestOutput::Execute(plan);
    verify(image_id, &journal);
    let GuestOutput::Execute(verified) = journal else {
        unreachable!("the journal was just constructed as a plan")
    };
    verified
}

fn verified_resolution(image_id: ProgramId, resolution: ResolveOutput) -> ResolveOutput {
    let journal = GuestOutput::Resolve(resolution);
    verify(image_id, &journal);
    let GuestOutput::Resolve(verified) = journal else {
        unreachable!("the journal was just constructed as a resolution")
    };
    verified
}

fn verify(image_id: ProgramId, journal: &GuestOutput) {
    env::verify(image_id, &lee_core::to_borsh_frame(journal))
        .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
}
