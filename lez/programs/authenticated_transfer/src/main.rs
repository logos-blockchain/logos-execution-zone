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
