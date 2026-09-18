use lee_core::program::{
    AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
};

/// A variant of `noop` that asserts every `pre_state.is_authorized == true` before echoing
/// the `post_diffs`. Any unauthorized `pre_state` panics the guest, failing the whole
/// circuit proof. Used as a callee in private-PDA delegation tests to actually exercise the
/// authorization propagated through `ChainedCall.pda_seeds`.
type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    for pre in &pre_states {
        assert!(
            pre.is_authorized,
            "auth_asserting_noop: pre_state {} is not authorized",
            pre.account_id
        );
    }

    let state_diffs = pre_states
        .iter()
        .map(|account| AccountStateDiff::unchanged(account.clone()))
        .collect();
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
