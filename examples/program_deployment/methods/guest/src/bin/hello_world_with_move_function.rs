use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{ProgramInput, ProgramOutput, read_lee_inputs},
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
// Execution succeeds only if:
// - the accounts involved are either uninitialized, or
// - already owned by this program.
//
// Writing data to an unowned input account is what makes this program its owner;
// `move_data` clears the source's data, which acquires nothing.

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

fn write(pre_state: AccountWithMetadata, greeting: &[u8]) -> Account {
    // Construct the post state account value. Writing data to an unowned account is what
    // makes this program its owner.
    let mut post_account = pre_state.account;
    let mut bytes = post_account.data.into_inner();
    bytes.extend_from_slice(greeting);
    post_account.data = bytes
        .try_into()
        .expect("Data should fit within the allowed limits");
    post_account
}

fn move_data(from_pre: AccountWithMetadata, to_pre: AccountWithMetadata) -> Vec<Account> {
    // Construct the post state account values
    let from_data: Vec<u8> = from_pre.account.data.clone().into();

    let from_post = {
        let mut this = from_pre.account;
        this.data = Data::default();
        this
    };

    let to_post = {
        let mut this = to_pre.account;
        let mut bytes = this.data.into_inner();
        bytes.extend_from_slice(&from_data);
        this.data = bytes
            .try_into()
            .expect("Data should fit within the allowed limits");
        this
    };

    vec![from_post, to_post]
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
            let post = write(account_pre.clone(), &data);
            vec![post]
        }
        ([account_from_pre, account_to_pre], MOVE_DATA_FUNCTION_ID, 0) => {
            move_data(account_from_pre.clone(), account_to_pre.clone())
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
