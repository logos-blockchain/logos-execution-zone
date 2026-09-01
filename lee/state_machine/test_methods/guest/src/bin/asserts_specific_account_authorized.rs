use lee_core::{
    account::AccountId,
    program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Asserts only the named account is authorized, ignoring every other pre_state it receives.
type Instruction = AccountId;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: account_to_check,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    if let Some(pre) = pre_states
        .iter()
        .find(|pre| pre.account_id == account_to_check)
    {
        assert!(
            pre.is_authorized,
            "asserts_specific_account_authorized: {account_to_check} is not authorized"
        );
    }

    let post_states = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
