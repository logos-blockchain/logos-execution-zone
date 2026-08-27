use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, read_lee_call},
};

type Instruction = u128;

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: balance,
    } = read_lee_call::<Instruction>();

    let single_account = match input.pre_states.as_slice() {
        [account_pre] => Some(AccountDiffOutput::new_claimed_if_default(
            AccountDiff::unchanged(account_pre.account_id),
            account_pre.account.program_owner,
            Claim::Authorized,
        )),
        _ => None,
    };
    if let Some(diff_output) = single_account {
        input.into_output(vec![diff_output]).write();
        return;
    }

    let [sender_pre, receiver_pre] = input.pre_states.as_slice() else {
        return;
    };
    let (sender_owner, receiver_owner) = (
        sender_pre.account.program_owner,
        receiver_pre.account.program_owner,
    );

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

    input
        .into_output(vec![
            AccountDiffOutput::new_claimed_if_default(sender_diff, sender_owner, Claim::Authorized),
            AccountDiffOutput::new_claimed_if_default(
                receiver_diff,
                receiver_owner,
                Claim::Authorized,
            ),
        ])
        .write();
}
