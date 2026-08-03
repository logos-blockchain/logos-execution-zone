use std::convert::Infallible;

use lee_core::{
    account::{Account, AccountDiff, AccountId, BalanceDiff, data::Data},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call, write_update_from_diff_output},
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
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

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };
    let extra_diff = AccountDiff {
        id: AccountId::default(),
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![
            AccountDiffOutput::new(diff),
            AccountDiffOutput::new(extra_diff),
        ],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, _diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(Data::default())
}
