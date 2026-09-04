use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

// Hello-world with authorization example program.
//
// This program reads an arbitrary sequence of bytes as its instruction
// and appends those bytes to the `data` field of the single input account.
//
// Execution succeeds only if the input account **is authorized**.
//
// The updated account is emitted as the sole post-state.

type Instruction = Vec<u8>;

fn main() {
    // Read inputs
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: greeting,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

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

    // Construct the new data value: the existing data with the greeting appended.
    let new_data = {
        let mut bytes = pre_state.account.data.clone().into_inner();
        bytes.extend_from_slice(&greeting);
        bytes
            .try_into()
            .expect("Data should fit within the allowed limits")
    };

    // Wrap the diff inside an `AccountStateDiff` instance.
    let post_state = AccountStateDiff::new(pre_state, BalanceDiff::Add(0), new_data);

    // The output is a proposed state difference. It will only succeed if the pre states coincide
    // with the previous values of the accounts, and the transition to the post states conforms
    // with the LEE program rules.
    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![post_state],
    )
    .write();
}
