use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{AccountInput, BalanceDiff},
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountInput,
    recipient: AccountInput,
    balance_to_move: u128,
) -> Vec<AccountStateDiff> {
    // Continue only if the sender has authorized this operation.
    assert!(sender.is_authorized, "Sender must be authorized");

    let sender_diff_output =
        AccountStateDiff::balance_only(sender, BalanceDiff::Sub(balance_to_move));

    let recipient_diff_output =
        AccountStateDiff::balance_only(recipient, BalanceDiff::Add(balance_to_move));

    vec![sender_diff_output, recipient_diff_output]
}

/// A transfer of balance program.
/// To be used both in public and private contexts.
fn main() {
    // Read input accounts.
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction:
                Instruction::Transfer {
                    amount: balance_to_move,
                },
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let [sender, recipient] =
        <[_; 2]>::try_from(pre_states).expect("Transfer requires exactly 2 accounts");
    let post_diffs = transfer(sender, recipient, balance_to_move);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_diffs,
    )
    .write();
}

#[cfg(test)]
mod tests {
    use lee_core::account::AccountId;

    use super::*;

    fn holder(seed: u8, balance: u128) -> AccountInput {
        AccountInput::balance_only(AccountId::new([seed; 32]), true, balance)
    }

    #[test]
    fn transfer_moves_the_amount_to_a_recipient_that_did_not_authorize() {
        let mut recipient = holder(1, 0);
        recipient.is_authorized = false;

        let diffs = transfer(holder(0, 100), recipient, 30);

        assert_eq!(diffs[0].post_balance_diff, BalanceDiff::Sub(30));
        assert_eq!(diffs[1].post_balance_diff, BalanceDiff::Add(30));
    }

    #[test]
    fn transfer_writes_no_data_whatever_shard_a_shard_selector_names() {
        let program = AccountId::new([9; 32]);
        let sender = AccountInput::with_shard(
            AccountId::new([0; 32]),
            true,
            100,
            program,
            b"record".to_vec().try_into().unwrap(),
        );

        let diffs = transfer(sender, holder(1, 0), 30);

        assert!(diffs.iter().all(|diff| diff.post_data.is_none()));
    }

    #[test]
    #[should_panic(expected = "Sender must be authorized")]
    fn transfer_refuses_an_unauthorized_sender() {
        let mut sender = holder(0, 100);
        sender.is_authorized = false;

        let diffs = transfer(sender, holder(1, 0), 30);

        unreachable!("an unauthorized sender must panic, got {diffs:?}");
    }
}
