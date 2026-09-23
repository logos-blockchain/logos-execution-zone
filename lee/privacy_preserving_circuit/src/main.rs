use lee_core::{
    PrivacyPreservingCircuitInput,
    program::{ChainedCall, read_input_frame},
    validation::validate_state_diff,
};
use risc0_zkvm::guest::env;

mod output;
mod private_backend;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        private_witnesses,
        program_account_id,
        dummy_inputs,
        ciphertext_padding,
        initial_shard_selectors,
        program_image_claims,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    let Some(first_output) = program_outputs.first() else {
        panic!("PrivacyPreservingCircuitInput::program_outputs is empty: nothing to validate");
    };
    // Only bootstraps the loop's first iteration: the top-level call is reached through a proof
    // rather than through a caller that named its shards, so it declares none of its own.
    let initial_call = ChainedCall {
        program_account_id,
        instruction_data: first_output.instruction_data.clone(),
        shard_selectors: Vec::new(),
        pda_seeds: Vec::new(),
    };
    let mut backend = private_backend::PrivateBackend::new(
        &private_witnesses,
        program_outputs,
        &program_image_claims,
        &initial_shard_selectors,
    );
    let threaded = match validate_state_diff(&mut backend, initial_call, &initial_shard_selectors) {
        Ok(threaded) => threaded,
        // `Fatal` is uninhabited: every rejection already panicked at its own failure site.
        Err(fatal) => match fatal {},
    };

    // An account with no witness has no note, so the verifier must be able to check it against
    // real chain state: expose it in the journal, in first-sight order.
    let public: Vec<_> = threaded
        .first_sight
        .iter()
        .filter(|(account_id, _)| backend.witness_for(*account_id).is_none())
        .map(|(account_id, is_authorized)| {
            (
                *account_id,
                *is_authorized,
                threaded.at_first_sight[account_id].clone(),
                threaded.touched[account_id].clone(),
            )
        })
        .collect();

    // Private accounts keep their full post state; the output stage turns each into a note.
    let mut private_final = threaded.touched;
    private_final.retain(|account_id, _| backend.witness_for(*account_id).is_some());

    let (block_validity_window, timestamp_validity_window) = backend.into_windows();

    let output = output::compute_circuit_output(
        block_validity_window,
        timestamp_validity_window,
        public,
        private_final,
        &private_witnesses,
        dummy_inputs,
        ciphertext_padding,
        program_image_claims,
    );

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}
