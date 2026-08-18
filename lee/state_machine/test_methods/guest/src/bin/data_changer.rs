use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, Data},
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
            let data = update_from_diff(&pre_state, &diff_data);
            write_update_from_diff_output(&pre_state, &diff_data, &data);
            return;
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let new_data: Data = data
        .try_into()
        .expect("provided data should fit into data limit");
    let account_id = pre.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new_claimed(
            AccountDiff {
                id: account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(new_data.as_ref().to_vec()),
            },
            Claim::Authorized,
        )],
    )
    .write();
}

/// The new data value is always a fully-computed byte blob assigned directly, so materializing
/// it from `diff_data` is a passthrough.
fn update_from_diff(_pre_state: &Account, diff_data: &[u8]) -> Data {
    diff_data
        .to_vec()
        .try_into()
        .expect("diff_data was already validated to fit under DATA_MAX_LENGTH when constructed")
}
