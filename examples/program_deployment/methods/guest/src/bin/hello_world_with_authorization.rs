use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, read_lee_call},
};

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
    let ProgramCall::Execute {
        input,
        instruction: greeting,
    } = read_lee_call::<Instruction>();

    // Unpack the input account pre state
    let [pre_state] = input.pre_states.as_slice() else {
        panic!("Input pre states should consist of a single account");
    };

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

    let diff = AccountDiff {
        id: pre_state.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(new_data),
    };

    // Wrap the diff inside an `AccountDiffOutput` instance.
    // This is used to forward the account claiming request if any
    let post_state = AccountDiffOutput::new_claimed_if_default(
        diff,
        pre_state.account.program_owner,
        Claim::Authorized,
    );

    // The output is a proposed state difference. It will only succeed if the pre states coincide
    // with the previous values of the accounts, and the transition to the post states conforms
    // with the LEE program rules.
    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    input.into_output(vec![post_state]).write();
}
