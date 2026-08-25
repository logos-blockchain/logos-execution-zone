use lee_core::program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ProgramId;

/// Writes data into a slot belonging to the program named in the instruction. Rule 4 must
/// reject the post: a program rewrites only its own slot.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: foreign_program_id,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut account_post = pre.account.clone();
    account_post.slot_mut(foreign_program_id).data = vec![0xBE_u8]
        .try_into()
        .expect("one byte fits into data limit");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![account_post],
    )
    .write();
}
