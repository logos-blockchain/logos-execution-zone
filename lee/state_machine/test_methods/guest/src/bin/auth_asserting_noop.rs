use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

/// A variant of `noop` that asserts every `pre_state.is_authorized == true` before echoing
/// the `post_states`. Any unauthorized `pre_state` panics the guest, failing the whole
/// circuit proof. Used as a callee in private-PDA delegation tests to actually exercise the
/// authorization propagated through `ChainedCall.pda_seeds`.
type Instruction = ();

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    for pre in &pre_states {
        assert!(
            pre.is_authorized,
            "auth_asserting_noop: pre_state {} is not authorized",
            pre.account_id
        );
    }

    let post_states = pre_states
        .iter()
        .map(|account| AccountDiffOutput::new(AccountDiff::unchanged(account.account_id)))
        .collect();
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
