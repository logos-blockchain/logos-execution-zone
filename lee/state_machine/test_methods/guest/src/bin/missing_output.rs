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

    let Ok([pre1, pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let post1 = pre1.unchanged();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre1, pre2],
        vec![post1],
    )
    .write();
}
