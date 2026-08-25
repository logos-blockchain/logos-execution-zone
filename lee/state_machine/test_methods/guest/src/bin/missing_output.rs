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

    let Ok([pre1, pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let account_id_pre1 = pre1.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre1, pre2],
        vec![AccountDiffOutput::new(AccountDiff::unchanged(
            account_id_pre1,
        ))],
    )
    .write();
}
