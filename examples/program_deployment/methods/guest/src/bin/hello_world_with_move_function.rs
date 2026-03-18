use nssa_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{
        AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, read_nssa_inputs, write_nssa_outputs,
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
//
// Execution succeeds only if:
// - the accounts involved are either uninitialized, or
// - already owned by this program.
//
// In case an input account is uninitialized, the program will claim it when
// producing the post-state.

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

fn build_post_state(post_account: Account) -> AccountPostState {
    if post_account.program_owner == DEFAULT_PROGRAM_ID {
        // This produces a claim request
        AccountPostState::new_claimed(post_account)
    } else {
        // This doesn't produce a claim request
        AccountPostState::new(post_account)
    }
}

fn write(pre_state: AccountWithMetadata, greeting: &[u8]) -> AccountPostState {
    // Construct the post state account values
    let post_account = {
        let mut this = pre_state.account;
        let mut bytes = this.data.into_inner();
        bytes.extend_from_slice(greeting);
        this.data = bytes
            .try_into()
            .expect("Data should fit within the allowed limits");
        this
    };

    build_post_state(post_account)
}

fn move_data(from_pre: AccountWithMetadata, to_pre: AccountWithMetadata) -> Vec<AccountPostState> {
    // Construct the post state account values
    let from_data: Vec<u8> = from_pre.account.data.clone().into();

    let from_post = {
        let mut this = from_pre.account;
        this.data = Data::default();
        build_post_state(this)
    };

    let to_post = {
        let mut this = to_pre.account;
        let mut bytes = this.data.into_inner();
        bytes.extend_from_slice(&from_data);
        this.data = bytes
            .try_into()
            .expect("Data should fit within the allowed limits");
        build_post_state(this)
    };

    vec![from_post, to_post]
}

fn main() {
    // Read input accounts.
    let (
        ProgramInput {
            pre_states,
            instruction: (function_id, data),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

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

    write_nssa_outputs(instruction_words, pre_states, post_states);
}
