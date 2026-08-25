use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = u128;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_data,
            pre_states,
            vec![account_pre.account],
        )
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let debit = |account: &mut lee_core::account::Account| {
        let slot = account.slot_mut(self_program_id);
        slot.balance = slot
            .balance
            .checked_sub(balance)
            .expect("Not enough balance to transfer");
    };
    let credit = |account: &mut lee_core::account::Account| {
        let slot = account.slot_mut(self_program_id);
        slot.balance = slot
            .balance
            .checked_add(balance)
            .expect("Overflow when adding balance");
    };

    let post_states = if sender_pre.account_id == receiver_pre.account_id {
        let mut joint = sender_pre.account.clone();
        debit(&mut joint);
        credit(&mut joint);
        joint.prune();
        vec![joint.clone(), joint]
    } else {
        let mut sender_post = sender_pre.account.clone();
        debit(&mut sender_post);
        sender_post.prune();
        let mut receiver_post = receiver_pre.account.clone();
        credit(&mut receiver_post);
        receiver_post.prune();
        vec![sender_post, receiver_post]
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![sender_pre, receiver_pre],
        post_states,
    )
    .write();
}
