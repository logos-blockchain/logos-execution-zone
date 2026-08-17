use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

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
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "simple_balance_transfer program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let account_post = AccountDiffOutput::new_claimed_if_default(
            AccountDiff {
                id: account_pre.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            },
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
    let sender_owner = sender_pre.account.program_owner;
    let receiver_owner = receiver_pre.account.program_owner;

    let sender_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: sender_pre.account_id,
            diff_balance: BalanceDiff::Sub(balance),
            diff_data: None,
        },
        sender_owner,
        Claim::Authorized,
    );
    let receiver_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: receiver_pre.account_id,
            diff_balance: BalanceDiff::Add(balance),
            diff_data: None,
        },
        receiver_owner,
        Claim::Authorized,
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender_pre, receiver_pre],
        vec![sender_post, receiver_post],
    )
    .write();
}
