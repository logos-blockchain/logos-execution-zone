use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff},
    program::{
        AccountDiffOutput, Claim, DEFAULT_PROGRAM_OWNER, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};

/// Initializes a default account under the ownership of this program.
fn initialize_account(pre_state: AccountWithMetadata) -> AccountDiffOutput {
    assert!(
        pre_state.account == Account::default(),
        "Account must be uninitialized"
    );

    AccountDiffOutput::new_claimed(
        AccountDiff::unchanged(pre_state.account_id),
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

    let sender_diff_output = AccountDiffOutput::new(AccountDiff {
        id: sender.account_id,
        diff_balance: BalanceDiff::Sub(balance_to_move),
        diff_data: None,
    });

    let recipient_diff = AccountDiff {
        id: recipient.account_id,
        diff_balance: BalanceDiff::Add(balance_to_move),
        diff_data: None,
    };
    // Claim recipient account if it has default program owner
    let recipient_diff_output = if recipient.account.program_owner == DEFAULT_PROGRAM_OWNER {
        AccountDiffOutput::new_claimed(recipient_diff, Claim::Authorized)
    } else {
        AccountDiffOutput::new(recipient_diff)
    };

    vec![sender_diff_output, recipient_diff_output]
}

/// A transfer of balance program.
/// To be used both in public and private contexts.
fn main() {
    // Read input accounts.
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

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
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
