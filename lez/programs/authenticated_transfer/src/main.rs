use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<Account> {
    // Continue only if the sender has authorized this operation.
    assert!(sender.is_authorized, "Sender must be authorized");

    // Create accounts post states, with updated balances
    let sender_post = {
        // Modify sender's balance
        let mut sender_post_account = sender.account;
        sender_post_account.balance = sender_post_account
            .balance
            .checked_sub(balance_to_move)
            .expect("Sender has insufficient balance");
        sender_post_account
    };

    let recipient_post = {
        // Modify recipient's balance.
        let mut recipient_post_account = recipient.account;
        recipient_post_account.balance = recipient_post_account
            .balance
            .checked_add(balance_to_move)
            .expect("Recipient balance overflow");
        recipient_post_account
    };

    vec![sender_post, recipient_post]
}

/// A transfer of balance program.
/// To be used both in public and private contexts.
fn main() {
    // Read input accounts.
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states = match instruction {
        Instruction::Transfer {
            amount: balance_to_move,
        } => {
            let [sender, recipient] = <[_; 2]>::try_from(pre_states.clone())
                .expect("Transfer requires exactly 2 accounts");
            transfer(sender, recipient, balance_to_move)
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
