use lee_core::{
    account::AccountId,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Asserts only the named account is authorized, ignoring every other `pre_state` it receives.
type Instruction = AccountId;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: account_to_check,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    if let Some(pre) = pre_states
        .iter()
        .find(|pre| pre.account_id == account_to_check)
    {
        assert!(
            pre.is_authorized,
            "asserts_specific_account_authorized: {account_to_check} is not authorized"
        );
    }

    let state_diffs = pre_states
        .into_iter()
        .map(AccountStateDiff::unchanged)
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
