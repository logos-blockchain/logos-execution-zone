use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
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

fn write(pre_state: AccountWithMetadata, greeting: &[u8]) -> AccountDiffOutput {
    // Construct the new data value
    let new_data: Data = {
        let mut bytes = pre_state.account.data.clone().into_inner();
        bytes.extend_from_slice(greeting);
        bytes
            .try_into()
            .expect("greeting fits under DATA_MAX_LENGTH")
    };

    AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: pre_state.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(new_data),
        },
        pre_state.account.program_owner.into(),
        Claim::Authorized,
    )
}

fn move_data(from_pre: AccountWithMetadata, to_pre: AccountWithMetadata) -> Vec<AccountDiffOutput> {
    // Construct the post state account values
    let from_data: Vec<u8> = from_pre.account.data.clone().into();

    let from_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: from_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(Data::default()),
        },
        from_pre.account.program_owner.into(),
        Claim::Authorized,
    );

    let to_post = {
        let mut bytes = to_pre.account.data.clone().into_inner();
        bytes.extend_from_slice(&from_data);
        let bytes: Data = bytes
            .try_into()
            .expect("moved data fits under DATA_MAX_LENGTH");
        AccountDiffOutput::new_claimed_if_default(
            AccountDiff {
                id: to_pre.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(bytes),
            },
            to_pre.account.program_owner.into(),
            Claim::Authorized,
        )
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
        instruction_words,
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
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}

fn update_from_diff(
    _pre_state: Account,
    diff_data: Data,
) -> Result<Data, std::convert::Infallible> {
    Ok(diff_data)
}
