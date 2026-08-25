use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, DEFAULT_PROGRAM_ID, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id: _, // ignore the correct ID
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|a| AccountDiffOutput::new(AccountDiff::unchanged(a.account_id)))
        .collect();

    // Deliberately output wrong self_program_id
    ProgramOutput::new(
        DEFAULT_PROGRAM_ID, // WRONG: should be self_program_id
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
