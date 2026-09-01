use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = u128;

/// Moves balance out of the SECOND account into the first — the direction a
/// callee handed someone else's account would take to help itself.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: amount,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([recipient, source]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let mut source_post = source.account.clone();
    source_post.balance = source_post
        .balance
        .checked_sub(amount)
        .expect("Not enough balance to transfer");

    let mut recipient_post = recipient.account.clone();
    recipient_post.balance = recipient_post
        .balance
        .checked_add(amount)
        .expect("Overflow when adding balance");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![recipient, source],
        vec![recipient_post, source_post],
    )
    .write();
}
