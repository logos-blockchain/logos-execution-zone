use nssa_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs};

/// A variant of `noop` that asserts every `pre_state.is_authorized == true` before echoing
/// the `post_states`. Any unauthorized `pre_state` panics the guest, failing the whole
/// circuit proof. Used as a callee in private-PDA delegation tests to actually exercise the
/// authorization propagated through `ChainedCall.pda_seeds`.
type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    for pre in &pre_states {
        assert!(
            pre.is_authorized,
            "auth_asserting_noop: pre_state {} is not authorized",
            pre.account_id
        );
    }

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
