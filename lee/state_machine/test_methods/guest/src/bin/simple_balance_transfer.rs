use std::convert::Infallible;

use lee_core::{account::{Account, AccountDiff, BalanceDiff, data::Data}, program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call, write_update_from_diff_output}};

type Instruction = u128;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance,
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

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let diff = AccountDiff {
            id: account_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        };
        let account_post = AccountDiffOutput::new_claimed_if_default(
            diff,
            account_pre.account.program_owner,
            Claim::Authorized,
        );

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![account_post],
        )
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let sender_diff = AccountDiff {
        id: sender_pre.account_id,
        diff_balance: BalanceDiff::Sub(balance),
        diff_data: None,
    };

    let receiver_diff = AccountDiff{
        id: receiver_pre.account_id,
        diff_balance: BalanceDiff::Add(balance),
        diff_data: None,
    };

    let sender_program_owner = sender_pre.account.program_owner;
    let receiver_program_owner = receiver_pre.account.program_owner;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender_pre, receiver_pre],
        vec![
            AccountDiffOutput::new_claimed_if_default(sender_diff, sender_program_owner, Claim::Authorized),
            AccountDiffOutput::new_claimed_if_default(receiver_diff, receiver_program_owner, Claim::Authorized),
        ],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, _diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(Data::default())
}
