use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = Vec<u8>;

/// A program that modifies the account data by setting bytes sent in instruction.
fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: data,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
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

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![diff_output],
    )
    .write();
}
