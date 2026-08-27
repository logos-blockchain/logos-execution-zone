use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, read_lee_call},
};

type Instruction = u128;

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: balance_to_burn,
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        return;
    };

    // Clamp to preserve the old saturating_sub semantics (burn at most what's there).
    let burned = balance_to_burn.min(pre.account.balance);
    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Sub(burned),
        diff_data: None,
    };

    input
        .into_output(vec![AccountDiffOutput::new(diff)])
        .write();
}
