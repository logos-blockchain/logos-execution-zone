use authenticated_transfer_core::Instruction;
use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
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
            AccountPostState::new_claimed(recipient_post_account, Claim::Authorized)
        } else {
            AccountPostState::new(recipient_post_account)
        }
    };

    vec![sender_post, recipient_post]
}

/// Mints `balance` into a new account at genesis (`block_id` == 0).
///
/// Claims the target account and sets its balance in a single operation.
fn mint(
    target: AccountWithMetadata,
    clock: AccountWithMetadata,
    balance: u128,
) -> Vec<AccountPostState> {
    assert_eq!(
        clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID,
        "Second account must be the clock account"
    );

    let clock_data = ClockAccountData::from_bytes(&clock.account.data.clone().into_inner());
    assert_eq!(
        clock_data.block_id, 0,
        "Mint can only execute at genesis (block_id must be 0)"
    );

    assert!(
        target.account == Account::default(),
        "Target account must be uninitialized"
    );

    let mut target_post_account = target.account;
    target_post_account.balance = balance;
    let target_post = AccountPostState::new_claimed(target_post_account, Claim::Authorized);

    let clock_post = AccountPostState::new(clock.account);

    vec![target_post, clock_post]
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
        Instruction::Mint { amount: balance } => {
            let [target, clock] = <[_; 2]>::try_from(pre_states.clone())
                .expect("Mint requires exactly 2 accounts: target, clock");
            mint(target, clock, balance)
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
