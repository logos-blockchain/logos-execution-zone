use std::collections::HashMap;

use lee_core::{
    PrivacyPreservingCircuitInput, ProgramImageWitness,
    account::AccountId,
    execution_state::ExecutionState,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramId, read_input_frame},
};
use private_backend::PrivateBackend;
use risc0_zkvm::guest::env;

mod output;
mod private_backend;

fn main() {
    let PrivacyPreservingCircuitInput {
        root,
        private_witnesses,
        dummy_inputs,
        ciphertext_padding,
        program_image_witnesses,
        shadow_program_witnesses,
        calls,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    // The sequencer checks disclosed images against chain state.
    // For undisclosed images, `to_claim` checks header immutability and derives the membership
    // root. Native token and loader accounts run protocol code and cannot claim guest images.
    assert!(
        !program_image_witnesses.iter().any(|witness| {
            let account_id = witness.account_id();
            account_id == NATIVE_TOKEN_PROGRAM_ID || account_id == PROGRAM_LOADER_ACCOUNT_ID
        }),
        "A reserved program account has no deployable bytecode to claim"
    );
    let mut image_id_by_account_id: HashMap<AccountId, ProgramId> = program_image_witnesses
        .iter()
        .map(|witness| (witness.account_id(), witness.image_id()))
        .collect();
    for witness in &shadow_program_witnesses {
        let account_id = AccountId::for_shadow_program(&witness.image_id);
        let previous = image_id_by_account_id.insert(account_id, witness.image_id);
        assert!(
            previous.is_none(),
            "account {account_id} claimed by both a program-image claim and a shadow witness"
        );
    }

    let state =
        ExecutionState::initialize(root, &private_witnesses).unwrap_or_else(|e| panic!("{e}"));
    let mut backend = PrivateBackend::new(image_id_by_account_id, calls);
    let outcome = state.run(&mut backend).unwrap_or_else(|e| panic!("{e}"));
    backend.finish();

    let program_image_claims = program_image_witnesses
        .iter()
        .map(ProgramImageWitness::to_claim)
        .collect::<Result<Vec<_>, _>>()
        .expect("every program image witness must produce a valid claim");

    let output = output::compute_circuit_output(
        outcome,
        &private_witnesses,
        dummy_inputs,
        ciphertext_padding,
        program_image_claims,
    );

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}
