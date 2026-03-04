#![expect(
    clippy::arithmetic_side_effects,
    reason = "This program is intentionally malicious and is expected to have side effects."
)]

use nssa_core::{
    account::{Account, AccountWithMetadata},
    program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs},
};

/// Initializes a default account under the ownership of this program.
/// This is achieved by a noop.
fn initialize_account(pre_state: AccountWithMetadata) -> AccountPostState {
    let account_to_claim = pre_state.account;
    let is_authorized = pre_state.is_authorized;

    // Continue only if the account to claim has default values
    assert!(
        account_to_claim == Account::default(),
        "Account is already initialized"
    );

    // Continue only if the owner authorized this operation
    assert!(is_authorized, "Missing required authorization");

    AccountPostState::new(account_to_claim)
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<AccountPostState> {
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

    vec![
        AccountPostState::new(sender_post),
        AccountPostState::new(recipient_post),
    ]
}

/// A transfer of balance program.
/// To be used both in public and private contexts.
fn main() {
    // Read input accounts.
    let (
        ProgramInput {
            pre_states,
            instruction: balance_to_move,
        },
        instruction_data,
    ) = read_nssa_inputs();

    let post_states = match (pre_states.as_slice(), balance_to_move) {
        ([account_to_claim], 0) => {
            let post = initialize_account(account_to_claim.clone());
            vec![post]
        }
        ([sender, recipient], balance_to_move) => {
            transfer(sender.clone(), recipient.clone(), balance_to_move)
        }
        _ => panic!("invalid params"),
    };
    write_nssa_outputs(instruction_data, pre_states, post_states);
}
