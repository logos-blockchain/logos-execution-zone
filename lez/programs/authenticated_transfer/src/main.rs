use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{Input, Slot},
    program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Moves `amount` from the sender's native slot to whichever slot the transaction named at the
/// recipient. The two positions name distinct slots, so one address may hold both roles.
fn transfer(
    sender: Input,
    recipient: Input,
    amount: u128,
    native_program_id: ProgramId,
) -> Vec<Option<Slot>> {
    assert!(sender.is_authorized, "Sender must be authorized");

    let mut sender_post = sender.into_slot_of(native_program_id);
    sender_post.balance = sender_post
        .balance
        .checked_sub(amount)
        .expect("Sender has insufficient balance");

    let mut recipient_post = recipient.into_caller_named_slot();
    recipient_post.balance = recipient_post
        .balance
        .checked_add(amount)
        .expect("Recipient balance overflow");

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
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states = match instruction {
        Instruction::Transfer { amount } => {
            let [sender, recipient] = <[_; 2]>::try_from(pre_states.clone())
                .expect("Transfer requires exactly 2 accounts");
            transfer(sender, recipient, amount, self_program_id)
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

#[cfg(test)]
mod tests {
    use lee_core::account::{AccountId, Data};

    use super::*;

    const NATIVE: ProgramId = [1; 8];
    const OTHER: ProgramId = [2; 8];

    fn holder(program: ProgramId, balance: u128) -> Input {
        Input {
            account_id: AccountId::new([0; 32]),
            is_authorized: true,
            slot: Some((
                program.into(),
                Slot {
                    balance,
                    data: Data::empty(),
                },
            )),
        }
    }

    #[test]
    fn transfer_moves_balance_between_the_two_named_slots() {
        let posts = transfer(holder(NATIVE, 100), holder(OTHER, 0), 30, NATIVE);

        assert_eq!(posts[0].as_ref().unwrap().balance, 70);
        assert_eq!(posts[1].as_ref().unwrap().balance, 30);
    }

    #[test]
    fn transfer_empties_a_slot_it_drains() {
        let posts = transfer(holder(NATIVE, 100), holder(OTHER, 0), 100, NATIVE);

        assert!(posts[0].as_ref().unwrap().is_empty());
    }

    #[test]
    #[should_panic(expected = "Position names another namespace")]
    fn transfer_refuses_a_sender_slot_that_is_not_native() {
        let posts = transfer(holder(OTHER, 100), holder(OTHER, 0), 30, NATIVE);

        unreachable!("debiting a non-native sender slot must panic, got {posts:?}");
    }

    #[test]
    #[should_panic(expected = "Sender must be authorized")]
    fn transfer_refuses_an_unauthorized_sender() {
        let mut sender = holder(NATIVE, 100);
        sender.is_authorized = false;

        let posts = transfer(sender, holder(OTHER, 0), 30, NATIVE);

        unreachable!("an unauthorized sender must panic, got {posts:?}");
    }
}
