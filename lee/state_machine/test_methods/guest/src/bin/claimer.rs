use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff_output =
        AccountDiffOutput::new_claimed(AccountDiff::unchanged(pre.account_id), Claim::Authorized);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![diff_output],
    )
    .write();
}
