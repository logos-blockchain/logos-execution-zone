use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, data::Data, data::DataTooBigError},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
};

type Instruction = (Option<Vec<u8>>, bool);

/// A program that optionally modifies the account data and optionally claims it — the two
/// decisions are independent of each other, unlike `data_changer` which always claims.
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
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&pre_state, &diff_data, &data);
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
    if let Some(data) = &data_opt {
        let _: Data = data
            .clone()
            .try_into()
            .expect("provided data should fit into data limit");
    }

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: data_opt,
    };

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

fn update_from_diff(_pre_state: Account, diff_data: Vec<u8>) -> Result<Data, DataTooBigError> {
    diff_data.try_into()
}
