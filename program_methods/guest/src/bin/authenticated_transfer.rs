use authenticated_transfer_core::Instruction;
use nssa_core::{
    account::{Account, AccountWithMetadata},
    program::{
        AccountPostState, Claim, DEFAULT_PROGRAM_ID, ProgramInput, ProgramOutput, read_nssa_inputs,
    },
};

/// Initializes a default account under the ownership of this program.
fn initialize_account(pre_state: AccountWithMetadata) -> AccountPostState {
    let account_to_claim = AccountPostState::new_claimed(pre_state.account, Claim::Authorized);

    // Continue only if the account to claim has default values
    assert!(
        account_to_claim.account() == &Account::default(),
        "Account must be uninitialized"
    );

    account_to_claim
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<AccountPostState> {
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
            AccountPostState::new_claimed(recipient_post_account, Claim::Authorized)
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
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states = match instruction {
        Instruction::Initialize => {
            let [account_to_claim] = <[_; 1]>::try_from(pre_states.clone())
                .expect("Initialize requires exactly 1 account");
            vec![initialize_account(account_to_claim)]
        }
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
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
