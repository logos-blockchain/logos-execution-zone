use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountDiffOutput::new(AccountDiff::unchanged(account.account_id)))
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
