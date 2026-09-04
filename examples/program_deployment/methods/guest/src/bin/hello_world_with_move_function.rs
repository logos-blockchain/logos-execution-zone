use lee_core::{
    account::{AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

// Hello-world with write + move_data example program.
//
// This program reads an instruction of the form `(function_id, data)` and
// dispatches to either:
//
// - `write`: appends `data` to the `data` field of a single input account.
// - `move_data`: moves all bytes from one account to another. The source account is cleared and the
//   destination account receives the appended bytes.

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

fn write(pre_state: &AccountWithMetadata, greeting: &[u8]) -> AccountStateDiff {
    // Construct the new data value: the existing data with the greeting appended.
    let new_data: Data = {
        let mut bytes = pre_state.account.data.clone().into_inner();
        bytes.extend_from_slice(greeting);
        bytes
            .try_into()
            .expect("Data should fit within the allowed limits")
    };

    AccountStateDiff::new(pre_state.clone(), BalanceDiff::Add(0), new_data)
}

fn move_data(
    from_pre: &AccountWithMetadata,
    to_pre: &AccountWithMetadata,
) -> Vec<AccountStateDiff> {
    // Construct the new data values.
    let from_data: Vec<u8> = from_pre.account.data.clone().into();

    let from_post = AccountStateDiff::new(from_pre.clone(), BalanceDiff::Add(0), Data::default());

    let to_post = {
        let mut bytes = to_pre.account.data.clone().into_inner();
        bytes.extend_from_slice(&from_data);
        let new_data: Data = bytes
            .try_into()
            .expect("Data should fit within the allowed limits");
        AccountStateDiff::new(to_pre.clone(), BalanceDiff::Add(0), new_data)
    };

    vec![from_post, to_post]
}

fn main() {
    // Read input accounts.
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (function_id, data),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs = match (pre_states.as_slice(), function_id, data.len()) {
        ([account_pre], WRITE_FUNCTION_ID, _) => {
            let post = write(account_pre, &data);
            vec![post]
        }
        ([account_from_pre, account_to_pre], MOVE_DATA_FUNCTION_ID, 0) => {
            move_data(account_from_pre, account_to_pre)
        }
        _ => panic!("invalid params"),
    };

    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
