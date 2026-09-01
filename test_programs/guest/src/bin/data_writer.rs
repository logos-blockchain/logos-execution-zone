use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = Vec<u8>;

/// Writes the instruction bytes into the account's data.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: data,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut post = pre.account.clone();
    post.data = data
        .try_into()
        .expect("provided data should fit into data limit");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![post],
    )
    .write();
}
