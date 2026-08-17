use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

/// Initializes a default account under the ownership of this program.
fn initialize_account(pre_state: AccountWithMetadata) -> AccountDiffOutput {
    // Continue only if the account to claim has default values.
    assert!(
        pre_state.account == Account::default(),
        "Account must be uninitialized"
    );

    AccountDiffOutput::new_claimed(
        AccountDiff {
            id: pre_state.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        },
        Claim::Authorized,
    )
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<AccountDiffOutput> {
    // Continue only if the sender has authorized this operation.
    assert!(sender.is_authorized, "Sender must be authorized");

    let sender_post = AccountDiffOutput::new(AccountDiff {
        id: sender.account_id,
        diff_balance: BalanceDiff::Sub(balance_to_move),
        diff_data: None,
    });

    // Claim recipient account if it has default program owner.
    let recipient_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: recipient.account_id,
            diff_balance: BalanceDiff::Add(balance_to_move),
            diff_data: None,
        },
        recipient.account.program_owner.into(),
        Claim::Authorized,
    );

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
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "authenticated_transfer program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

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
