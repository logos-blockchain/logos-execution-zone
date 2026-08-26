use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

// Hello-world example program.
//
// This program reads an arbitrary sequence of bytes as its instruction
// and appends those bytes to the `data` field of the single input account.
//
// The program is handed this program's slot at the input account and writes it back; no other
// namespace at that account is reachable from here.
//
// The updated slot is emitted as the sole post-state.

type Instruction = Vec<u8>;

fn main() {
    // Read inputs
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: greeting,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    // Unpack the input account pre state
    let [pre_state] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));

    // Construct the post state account values
    let post_state = {
        let mut this = pre_state.slot_of(self_program_id).clone();
        let mut bytes = this.data.clone().into_inner();
        bytes.extend_from_slice(&greeting);
        this.data = bytes
            .try_into()
            .expect("Data should fit within the allowed limits");
        Some(this)
    };

    // The output is a proposed state difference. It will only succeed if the pre states coincide
    // with the previous values of the accounts, and the transition to the post states conforms
    // with the LEE program rules.
    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre_state],
        vec![post_state],
    )
    .write();
}
