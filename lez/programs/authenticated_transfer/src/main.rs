use authenticated_transfer_core::Instruction;
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Transfers `amount` native balance from `sender`'s native slot to `recipient_slot` at the
/// recipient. One address may play both roles; the posts then agree by construction.
fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    amount: u128,
    native_program_id: ProgramId,
    recipient_slot: ProgramId,
) -> Vec<Account> {
    // Continue only if the sender has authorized this operation.
    assert!(sender.is_authorized, "Sender must be authorized");

    let debit = |account: &mut Account| {
        let slot = account.slot_mut(native_program_id);
        slot.balance = slot
            .balance
            .checked_sub(amount)
            .expect("Sender has insufficient balance");
    };
    let credit = |account: &mut Account| {
        let slot = account.slot_mut(recipient_slot);
        slot.balance = slot
            .balance
            .checked_add(amount)
            .expect("Recipient balance overflow");
    };

    if sender.account_id == recipient.account_id {
        let mut joint = sender.account;
        debit(&mut joint);
        credit(&mut joint);
        joint.prune();
        return vec![joint.clone(), joint];
    }

    let mut sender_post = sender.account;
    debit(&mut sender_post);
    sender_post.prune();

    let mut recipient_post = recipient.account;
    credit(&mut recipient_post);
    recipient_post.prune();

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
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states = match instruction {
        Instruction::Transfer {
            amount,
            recipient_program,
        } => {
            let [sender, recipient] = <[_; 2]>::try_from(pre_states.clone())
                .expect("Transfer requires exactly 2 accounts");
            let recipient_slot = recipient_program.unwrap_or(self_program_id);
            transfer(sender, recipient, amount, self_program_id, recipient_slot)
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
    use lee_core::account::{AccountId, Data, Nonce};

    use super::*;

    const NATIVE: ProgramId = [1; 8];
    const OTHER: ProgramId = [2; 8];

    fn holder(balance: u128) -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::single(NATIVE, balance, Data::empty(), Nonce(0)),
            is_authorized: true,
            account_id: AccountId::new([0; 32]),
        }
    }

    #[test]
    fn self_transfer_within_one_slot_is_a_no_op() {
        let holder = holder(100);

        let posts = transfer(holder.clone(), holder, 30, NATIVE, NATIVE);

        assert_eq!(
            posts[0], posts[1],
            "both roles must agree on the one account"
        );
        assert_eq!(posts[0].balance(NATIVE), 100);
    }

    #[test]
    fn self_transfer_across_slots_leaves_two_slots_on_one_account() {
        let holder = holder(100);

        let posts = transfer(holder.clone(), holder, 30, NATIVE, OTHER);

        assert_eq!(posts[0], posts[1]);
        assert_eq!(posts[0].balance(NATIVE), 70);
        assert_eq!(posts[0].balance(OTHER), 30);
        assert_eq!(posts[0].slots.len(), 2);
    }

    #[test]
    fn self_transfer_of_the_whole_balance_prunes_the_source_slot() {
        let holder = holder(100);

        let posts = transfer(holder.clone(), holder, 100, NATIVE, OTHER);

        assert_eq!(posts[0].balance(OTHER), 100);
        assert_eq!(
            posts[0].slots.len(),
            1,
            "the emptied source slot must not be stored"
        );
    }
}
