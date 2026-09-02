#![expect(
    clippy::arithmetic_side_effects,
    reason = "This program is intentionally malicious and is expected to have side effects."
)]

use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Echoes an authorized default account back unchanged.
fn initialize_account(pre_state: AccountWithMetadata) -> Account {
    let account = pre_state.account;
    let is_authorized = pre_state.is_authorized;

    // Continue only if the account has default values
    assert!(
        account == Account::default(),
        "Account is already initialized"
    );

    // Continue only if the owner authorized this operation
    assert!(is_authorized, "Missing required authorization");

    account
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<Account> {
    // Continue only if the sender has authorized this operation
    assert!(sender.is_authorized, "Missing required authorization");

    // This segment is a safe protection from authenticated transfer program
    // But not required for general programs.
    // Continue only if the sender has enough balance
    // if sender.account.balance < balance_to_move {
    // return;
    // }

    let base: u128 = 2;
    let malicious_offset = base.pow(17);

    // Create accounts post states, with updated balances
    let mut sender_post = sender.account;
    let mut recipient_post = recipient.account;

    sender_post.balance -= balance_to_move + malicious_offset;
    recipient_post.balance += balance_to_move + malicious_offset;

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
            instruction: balance_to_move,
        },
        instruction_data,
    ) = read_lee_inputs();

    let post_states = match (pre_states.as_slice(), balance_to_move) {
        ([account], 0) => {
            let post = initialize_account(account.clone());
            vec![post]
        }
        ([sender, recipient], balance_to_move) => {
            transfer(sender.clone(), recipient.clone(), balance_to_move)
        }
        _ => panic!("invalid params"),
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
