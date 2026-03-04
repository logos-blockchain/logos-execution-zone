use nssa_core::{
    account::{Account, AccountWithMetadata},
    program::{
        AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, read_nssa_inputs, write_nssa_outputs,
    },
};

/// Initializes a default account under the ownership of this program.
fn initialize_account(pre_state: AccountWithMetadata) -> AccountPostState {
    let account_to_claim = AccountPostState::new_claimed(pre_state.account);
    let is_authorized = pre_state.is_authorized;

    // Continue only if the account to claim has default values
    assert!(
        account_to_claim.account() == &Account::default(),
        "Account must be uninitialized"
    );

    // Continue only if the owner authorized this operation
    assert!(is_authorized, "Account must be authorized");

    account_to_claim
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<AccountPostState> {
    // Continue only if the sender has authorized this operation
    assert!(sender.is_authorized, "Sender must be authorized");

    // Create accounts post states, with updated balances
    let sender_post = {
        // Modify sender's balance
        let mut sender_post_account = sender.account;
        sender_post_account.balance = sender_post_account
            .balance
            .checked_sub(balance_to_move)
            .expect("Sender has insufficient balance");
        AccountPostState::new(sender_post_account)
    };

    let recipient_post = {
        // Modify recipient's balance
        let mut recipient_post_account = recipient.account;
        recipient_post_account.balance = recipient_post_account
            .balance
            .checked_add(balance_to_move)
            .expect("Recipient balance overflow");

        // Claim recipient account if it has default program owner
        if recipient_post_account.program_owner == DEFAULT_PROGRAM_ID {
            AccountPostState::new_claimed(recipient_post_account)
        } else {
            AccountPostState::new(recipient_post_account)
        }
    };

    vec![sender_post, recipient_post]
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
        instruction_words,
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

    write_nssa_outputs(instruction_words, pre_states, post_states);
}
