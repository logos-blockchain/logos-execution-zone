use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{Account, AccountWithMetadata, BalanceDiff},
    program::{
        AccountStateDiff, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Initializes a default account under the ownership of this program.
fn initialize_account(pre_state: AccountWithMetadata) -> AccountStateDiff {
    assert!(
        pre_state.account == Account::default(),
        "Account must be uninitialized"
    );

    AccountStateDiff::new_claimed(
        pre_state.clone(),
        BalanceDiff::Add(0),
        pre_state.account.data.clone(),
        Claim::Authorized,
    )
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<AccountStateDiff> {
    // Continue only if the sender has authorized this operation.
    assert!(sender.is_authorized, "Sender must be authorized");

    let sender_diff_output = AccountStateDiff::new(
        sender.clone(),
        BalanceDiff::Sub(balance_to_move),
        sender.account.data.clone(),
    );

    // Claim recipient account if it has default program owner
    let recipient_diff_output = AccountStateDiff::new_claimed_if_default(
        recipient.clone(),
        BalanceDiff::Add(balance_to_move),
        recipient.account.data.clone(),
        Claim::Authorized,
    );

    vec![sender_diff_output, recipient_diff_output]
}

/// A transfer of balance program.
/// To be used both in public and private contexts.
fn main() {
    // Read input accounts.
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let post_diffs = match instruction {
        Instruction::Initialize => {
            let [account_to_claim] =
                <[_; 1]>::try_from(pre_states).expect("Initialize requires exactly 1 account");
            vec![initialize_account(account_to_claim)]
        }
        Instruction::Transfer {
            amount: balance_to_move,
        } => {
            let [sender, recipient] =
                <[_; 2]>::try_from(pre_states).expect("Transfer requires exactly 2 accounts");
            transfer(sender, recipient, balance_to_move)
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        post_diffs,
    )
    .write();
}
