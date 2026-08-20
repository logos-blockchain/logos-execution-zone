use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
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
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: greeting,
        },
        instruction_data,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(pre_state, diff_data, data);
            return;
        }
    };

    // Unpack the input account pre state
    let [pre_state] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));

    // Construct the new data value
    let new_data: Data = {
        let mut bytes = pre_state.account.data.clone().into_inner();
        bytes.extend_from_slice(&greeting);
        bytes
            .try_into()
            .expect("greeting fits under DATA_MAX_LENGTH")
    };

    // Wrap the diff inside a `AccountDiffOutput` instance.
    // This is used to forward the account claiming request if any
    let post_state = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: pre_state.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(new_data),
        },
        pre_state.account.program_owner.into(),
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

fn update_from_diff(
    _pre_state: Account,
    diff_data: Data,
) -> Result<Data, std::convert::Infallible> {
    Ok(diff_data)
}
