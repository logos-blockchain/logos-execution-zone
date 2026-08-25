use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

// Hello-world example program.
//
// This program reads an arbitrary sequence of bytes as its instruction
// and appends those bytes to the `data` field of the single input account.
//
// Execution succeeds only if the input account is either:
// - uninitialized, or
// - already owned by this program.
//
// In case the input account is uninitialized, the program claims it.
//
// The updated account is emitted as the sole post-state.

type Instruction = Vec<u8>;

fn main() {
    // Read inputs
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: greeting,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    // Unpack the input account pre state
    let [pre_state] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));

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
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre_state],
        vec![post_state],
    )
    .write();
}
