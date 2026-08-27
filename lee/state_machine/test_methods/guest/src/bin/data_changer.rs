use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, read_lee_call},
};

type Instruction = Vec<u8>;

/// A program that modifies the account data by setting bytes sent in instruction.
fn main() {
    let ProgramCall::Execute {
        input,
        instruction: data,
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        return;
    };

    let diff_output = AccountDiffOutput::new_claimed(
        AccountDiff {
            id: pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(
                data.try_into()
                    .expect("provided data should fit into data limit"),
            ),
        },
        Claim::Authorized,
    );

    input.into_output(vec![diff_output]).write();
}
