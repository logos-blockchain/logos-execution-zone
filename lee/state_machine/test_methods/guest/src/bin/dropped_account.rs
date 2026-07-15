use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

/// Silently drops the second account entirely from its own output: given two `pre_states`, it
/// returns only one `(pre, post)` pair, echoing the first account back unchanged.
///
/// Unlike `missing_output` (whose own `pre_states.len() != post_states.len()`, tripping
/// `validate_execution`'s internal length check directly), this program's own output is
/// internally consistent — one `pre_state` and one matching `post_state` — it just reports fewer
/// accounts than it was handed. This mirrors a well-behaved-looking dispatcher that filters an
/// account out of both sides of its output together (e.g. a stale-signer-nonce workaround that's
/// too broad), rather than an obviously malformed program.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre1, _pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let account_pre1 = pre1.account.clone();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre1],
        vec![AccountPostState::new(account_pre1)],
    )
    .write();
}
