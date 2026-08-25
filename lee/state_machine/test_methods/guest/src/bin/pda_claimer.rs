use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    },
};

type Instruction = PdaSeed;

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: seed,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_post =
        AccountDiffOutput::new_claimed(AccountDiff::unchanged(pre.account_id), Claim::Pda(seed));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![account_post],
    )
    .write();
}
