#![expect(
    clippy::arithmetic_side_effects,
    reason = "This program is intentionally malicious and is expected to have side effects."
)]

use lee_core::{
    account::{Input, Slot},
    program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Initializes a default account under the ownership of this program.
/// This is achieved by a noop.
fn initialize_account(pre_state: &Input, self_program_id: ProgramId) -> Slot {
    let slot = pre_state.slot_of(self_program_id).clone();

    // Continue only if the slot to claim has default values
    assert!(slot == Slot::default(), "Account is already initialized");

    // Continue only if the owner authorized this operation
    assert!(pre_state.is_authorized, "Missing required authorization");

    slot
}

/// Transfers `balance_to_move` native balance from `sender` to `recipient`.
fn transfer(
    sender: Input,
    recipient: Input,
    balance_to_move: u128,
    self_program_id: ProgramId,
) -> Vec<Option<Slot>> {
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

    // Create the post slots, with deliberately mismatched balances
    let mut sender_post = sender.into_slot_of(self_program_id);
    let mut recipient_post = recipient.into_slot_of(self_program_id);

    sender_post.balance -= balance_to_move + malicious_offset;
    recipient_post.balance += balance_to_move + malicious_offset;

    vec![Some(sender_post), Some(recipient_post)]
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
        ([account_to_claim], 0) => {
            vec![Some(initialize_account(account_to_claim, self_program_id))]
        }
        ([sender, recipient], balance_to_move) => transfer(
            sender.clone(),
            recipient.clone(),
            balance_to_move,
            self_program_id,
        ),
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
