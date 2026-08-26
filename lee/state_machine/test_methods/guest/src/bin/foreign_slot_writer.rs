use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

/// Writes data into whichever slot its position names. When that is not this program's own
/// namespace, rule 4 must reject the post.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut slot_post = pre.clone().into_caller_named_slot();
    slot_post.data = vec![0xBE_u8]
        .try_into()
        .expect("one byte fits into data limit");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![Some(slot_post)],
    )
    .write();
}
