use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = u128;

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let diff_output = AccountDiffOutput::new_claimed_if_default(
            AccountDiff::unchanged(account_pre.account_id),
            account_pre.account.program_owner,
            Claim::Authorized,
        );

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_data,
            pre_states,
            vec![diff_output],
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
    let receiver_diff = AccountDiff {
        id: receiver_pre.account_id,
        diff_balance: BalanceDiff::Add(balance),
        diff_data: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![sender_pre.clone(), receiver_pre.clone()],
        vec![
            AccountDiffOutput::new_claimed_if_default(
                sender_diff,
                sender_pre.account.program_owner,
                Claim::Authorized,
            ),
            AccountDiffOutput::new_claimed_if_default(
                receiver_diff,
                receiver_pre.account.program_owner,
                Claim::Authorized,
            ),
        ],
    )
    .write();
}
