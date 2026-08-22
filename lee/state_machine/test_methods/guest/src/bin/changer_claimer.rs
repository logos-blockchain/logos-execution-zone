use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
};

type Instruction = (Option<Vec<u8>>, bool);

/// A program that optionally modifies the account data and optionally claims it.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (data_opt, should_claim),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone());
            write_update_from_diff_output(pre_state, diff_data, data);
            return;
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Update data if provided.
    let diff_data: Option<Data> = data_opt.map(|data| {
        data.try_into()
            .expect("provided data should fit into data limit")
    });

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data,
    };

    // Claim or not based on the boolean flag.
    let post_state = if should_claim {
        AccountDiffOutput::new_claimed(diff, Claim::Authorized)
    } else {
        AccountDiffOutput::new(diff)
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![post_state],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, diff_data: Data) -> Data {
    diff_data
}
