use lee_core::{account::{Account, AccountDiff, BalanceDiff, BalanceDiffError}, program::{AccountDiffOutput, Claim, ProgramInput, ProgramOutput, read_lee_inputs}};

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
    ) = read_lee_inputs::<Instruction>();

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let diff = AccountDiff {
            id: account_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            raw_diff: None,
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

   // let mut sender_post = sender_pre.account.clone();
  //  let mut receiver_post = receiver_pre.account.clone();

    let sender_diff = AccountDiff {
        id: sender_pre.account_id,
        diff_balance: BalanceDiff::Sub(balance),
        raw_diff: None,
    };

    let receiver_diff = AccountDiff{
        id: receiver_pre.account_id,
        diff_balance: BalanceDiff::Add(balance),
        raw_diff: None,
    };

    let sender_program_owner = sender_pre.account.program_owner;
    let receiver_program_owner = receiver_pre.account.program_owner;


    /*
    Marvin-todo: original code: to delete
    sender_post.balance = sender_post
        .balance
        .checked_sub(balance)
        .expect("Not enough balance to transfer");
    receiver_post.balance = receiver_post
        .balance
        .checked_add(balance)
        .expect("Overflow when adding balance");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender_pre, receiver_pre],
        vec![
            AccountPostState::new_claimed_if_default(sender_post, Claim::Authorized),
            AccountPostState::new_claimed_if_default(receiver_post, Claim::Authorized),
        ],
    )
    .write();
    */

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


#[expect(
    dead_code,
    reason = "placeholder: this program only touches balance, so apply_balance_diff alone is \
              sufficient for now and the orchestrator calls it directly. This becomes the real \
              per-program materialization function once raw_diff/data handling exists."
)]
fn update_from_diff(pre_state: Account, _diff: AccountDiff) -> Result<Account, BalanceDiffError> {
    Ok(pre_state)
}