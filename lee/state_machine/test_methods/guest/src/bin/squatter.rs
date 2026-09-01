use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

/// The data to write into the first account, and the balance to move out of it.
type Instruction = (Vec<u8>, u128);

/// Writes data to an account it does not own — acquiring it — and moves balance
/// out of it in the same breath.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (data, amount),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([target, recipient]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let mut target_post = target.account.clone();
    target_post.data = data
        .try_into()
        .expect("provided data should fit into data limit");
    target_post.balance = target_post
        .balance
        .checked_sub(amount)
        .expect("Not enough balance to move");

    let mut recipient_post = recipient.account.clone();
    recipient_post.balance = recipient_post
        .balance
        .checked_add(amount)
        .expect("Overflow when adding balance");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![target, recipient],
        vec![target_post, recipient_post],
    )
    .write();
}
