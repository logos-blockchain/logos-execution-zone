use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Deliberately mints: conservation must reject this.
    let mut slot_post = pre.slot_of(self_program_id).clone();
    slot_post.balance = slot_post.balance.checked_add(1).expect("Balance overflow");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![Some(slot_post)],
    )
    .write();
}
