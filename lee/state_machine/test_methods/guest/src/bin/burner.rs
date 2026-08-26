use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = u128;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance_to_burn,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Deliberately burns: conservation must reject this.
    let mut slot_post = pre.slot_of(self_program_id).clone();
    slot_post.balance = slot_post.balance.saturating_sub(balance_to_burn);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![Some(slot_post)],
    )
    .write();
}
