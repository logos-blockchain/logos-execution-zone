use lee_core::program::{
    AccountStateDiff, DeferReads, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_probe, respond_unsupported_call,
};

type Instruction = ();

/// Like `noop`, but `Incremental`-aware: asserts `DeferReads::All` on `Probe` instead of
/// responding `UnsupportedCallKind`. Lets a call chain terminate on an account it doesn't own
/// without forcing `Bound` — plain `noop` would, since it doesn't implement `Incremental` at all.
fn main() {
    let call = read_lee_call::<Instruction>();
    match call {
        ProgramCall::Execute(
            ProgramInput {
                self_account_id,
                caller_account_id,
                pre_states,
                ..
            },
            instruction_data,
        ) => {
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
        ProgramCall::Probe(input) => {
            respond_probe(&input, Some(DeferReads::All));
        }
        ProgramCall::Unsupported(..) | _ => respond_unsupported_call(call),
    }
}
