use lee_core::{
    account::{Data, Input, Slot},
    program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

// Hello-world with write + move_data example program.
//
// This program reads an instruction of the form `(function_id, data)` and
// dispatches to either:
//
// - `write`: appends `data` to the `data` field of a single input account.
// - `move_data`: moves all bytes from one account to another. The source account is cleared and the
//   destination account receives the appended bytes.
//
// Every position hands this program its own slot at that account, so the moved bytes never leave
// this program's namespace.

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

fn write(pre_state: &Input, greeting: &[u8], self_program_id: ProgramId) -> Slot {
    let mut this = pre_state.slot_of(self_program_id).clone();
    let mut bytes = this.data.clone().into_inner();
    bytes.extend_from_slice(greeting);
    this.data = bytes
        .try_into()
        .expect("Data should fit within the allowed limits");
    this
}

fn move_data(from_pre: &Input, to_pre: &Input, self_program_id: ProgramId) -> Vec<Option<Slot>> {
    let from_data: Vec<u8> = from_pre.data(self_program_id).clone().into();

    let from_post = {
        let mut this = from_pre.slot_of(self_program_id).clone();
        this.data = Data::default();
        this
    };

    let to_post = write(to_pre, &from_data, self_program_id);

    vec![Some(from_post), Some(to_post)]
}

fn main() {
    // Read input accounts.
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (function_id, data),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states = match (pre_states.as_slice(), function_id, data.len()) {
        ([account_pre], WRITE_FUNCTION_ID, _) => {
            vec![Some(write(account_pre, &data, self_program_id))]
        }
        ([account_from_pre, account_to_pre], MOVE_DATA_FUNCTION_ID, 0) => {
            move_data(account_from_pre, account_to_pre, self_program_id)
        }
        _ => panic!("invalid params"),
    };

    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
