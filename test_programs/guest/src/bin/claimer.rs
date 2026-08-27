use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, Claim, ProgramCall, read_lee_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        return;
    };

    let account_post =
        AccountDiffOutput::new_claimed(AccountDiff::unchanged(pre.account_id), Claim::Authorized);

    input.into_output(vec![account_post]).write();
}
