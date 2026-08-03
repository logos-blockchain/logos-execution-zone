use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, data::Data, data::DataTooBigError},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
};

type Instruction = Vec<u8>;

/// A program that modifies the account data by setting bytes sent in instruction.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: data,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data =
                update_from_diff(pre_state, diff_data).expect("update_from_diff should not fail");
            write_update_from_diff_output(&data);
            return;
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Sanity check only — the authoritative check happens wherever `diff_data` actually gets
    // applied (`update_from_diff`, invoked separately as a `CallKind::UpdateFromDiff` call);
    // this just gives an early, in-guest failure for the same case, same as the program did
    // before.
    let _: Data = data
        .clone()
        .try_into()
        .expect("provided data should fit into data limit");

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(data),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new_claimed(diff, Claim::Authorized)],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, diff_data: Vec<u8>) -> Result<Data, DataTooBigError> {
    diff_data.try_into()
}
