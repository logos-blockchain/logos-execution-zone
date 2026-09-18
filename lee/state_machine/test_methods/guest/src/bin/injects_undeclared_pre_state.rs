use lee_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Echoes its real `pre_states` unchanged, then appends one fabricated, untouched account never
/// present in its own input — to test whether reporting it in `ProgramOutput.state_diffs` alone
/// is enough to get it resolved, independent of `ChainedCall.pre_state_ids`.
type Instruction = AccountId;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: fabricated_account_id,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let mut state_diffs: Vec<AccountStateDiff> = pre_states
        .into_iter()
        .map(AccountStateDiff::unchanged)
        .collect();

    state_diffs.push(AccountStateDiff::unchanged(AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: fabricated_account_id,
    }));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
