use std::{collections::HashMap, convert::Infallible};

use lee_core::{
    PrivacyPreservingCircuitInput,
    account::AccountId,
    execution_state::ExecutionState,
    program::{ProgramId, read_input_frame},
};
use risc0_zkvm::guest::env;

mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        root,
        root_call_kind,
        mut public_facts,
        private_witnesses,
        dummy_inputs,
        program_image_claims,
        effects,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    // Untrusted claims supplied by the prover: `env::verify` needs a real image id, not an
    // arbitrary dispatch address. The circuit does not check these against real chain state —
    // the sequencer does that independently (`V03State::get_program_image_id`) before
    // accepting the proof, which fails naturally if a claim is a lie (the receipt's actually
    // committed bytes won't match the reconstructed output). See `ProgramImageClaim`.
    let image_id_by_account_id: HashMap<AccountId, ProgramId> = program_image_claims
        .iter()
        .map(|claim| (claim.account_id, claim.image_id))
        .collect();

    let mut state =
        ExecutionState::initialize(root, root_call_kind, &private_witnesses, &mut public_facts)
            .unwrap_or_else(|e| panic!("{e}"));

    for call_effects in effects {
        state
            .prepare_next_call(&mut public_facts)
            .unwrap_or_else(|e| panic!("{e}"))
            .expect("Program effects supplied for a call nothing scheduled");
        state
            .complete_call(call_effects, |output| {
                let image_id = image_id_by_account_id
                    .get(&output.self_account_id)
                    .expect("no image_id claim supplied for invoked program account");
                env::verify(*image_id, &lee_core::to_borsh_frame(output)).unwrap_or_else(
                    |_: Infallible| unreachable!("Infallible error is never constructed"),
                );
            })
            .unwrap_or_else(|e| panic!("{e}"));
    }

    let final_state = state.finish().unwrap_or_else(|e| panic!("{e}"));

    let output = output::compute_circuit_output(
        final_state,
        &private_witnesses,
        dummy_inputs,
        program_image_claims,
    );

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}
