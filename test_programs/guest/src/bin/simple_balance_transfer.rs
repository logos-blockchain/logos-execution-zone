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
            vec![account_pre.unchanged()],
        )
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    // No joint branch: two positions naming the same slot are rejected as duplicates before
    // a program ever runs, and two naming different slots are just two ordinary positions.
    let post_states = {
        let mut sender_post = sender_pre.slot_of(self_program_id).clone();
        sender_post.balance = sender_post
            .balance
            .checked_sub(balance)
            .expect("Not enough balance to transfer");

        let mut receiver_post = receiver_pre.slot_of(self_program_id).clone();
        receiver_post.balance = receiver_post
            .balance
            .checked_add(balance)
            .expect("Overflow when adding balance");

        vec![Some(sender_post), Some(receiver_post)]
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
