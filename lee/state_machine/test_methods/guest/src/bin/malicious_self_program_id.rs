use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, CallContext, DEFAULT_PROGRAM_ID, ProgramCall, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();
    let ProgramInput {
        call:
            CallContext {
                self_program_id: _, // ignore the correct ID
                caller_program_id,
                instruction_data,
            },
        pre_states,
    } = input;

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
