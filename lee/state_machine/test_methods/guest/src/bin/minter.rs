use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, read_lee_call},
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

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(1),
        diff_data: None,
    };

    input
        .into_output(vec![AccountDiffOutput::new(diff)])
        .write();
}
