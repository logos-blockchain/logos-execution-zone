use nssa_core::program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_nssa_inputs};

// Hello-world with authorization example program.
//
// This program reads an arbitrary sequence of bytes as its instruction
// and appends those bytes to the `data` field of the single input account.
//
// Execution succeeds only if the input account **is authorized** and is either:
// - uninitialized, or
// - already owned by this program.
//
// In case the input account is uninitialized, the program claims it.
//
// The updated account is emitted as the sole post-state.

type Instruction = Vec<u8>;

fn main() {
    // Read inputs
    let (
        ProgramInput { self_program_id,
            pre_states,
            instruction: greeting,
        },
        instruction_data,
    ) = read_nssa_inputs::<Instruction>();

    // Unpack the input account pre state
    let [pre_state] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));

    // #### Difference with `hello_world` example here:
    // Fail if the input account is not authorized
    // The `is_authorized` field will be correctly populated or verified by the system if
    // authorization is provided.
    assert!(pre_state.is_authorized, "Missing required authorization");
    // ####

    // Construct the post state account values
    let post_account = {
        let mut this = pre_state.account.clone();
        let mut bytes = this.data.into_inner();
        bytes.extend_from_slice(&greeting);
        this.data = bytes
            .try_into()
            .expect("Data should fit within the allowed limits");
        this
    };

    // Wrap the post state account values inside a `AccountPostState` instance.
    // This is used to forward the account claiming request if any
    let post_state = AccountPostState::new_claimed_if_default(post_account, Claim::Authorized);

    // The output is a proposed state difference. It will only succeed if the pre states coincide
    // with the previous values of the accounts, and the transition to the post states conforms
    // with the NSSA program rules.
    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    ProgramOutput::new(self_program_id, instruction_data, vec![pre_state], vec![post_state]).write();
}
