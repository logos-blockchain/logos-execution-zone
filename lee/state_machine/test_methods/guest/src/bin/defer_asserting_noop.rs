use lee_core::program::{
    AccountStateDiff, CallKind, DeferReads, IncrementalCall, ProgramCall, ProgramEvent,
    ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
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
        ProgramCall::Incremental(ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: instruction_data,
        }) => {
            let Ok(IncrementalCall::Probe(_)) = borsh::from_slice::<IncrementalCall>(&instruction_data)
            else {
                respond_unsupported_call(ProgramCall::<Instruction>::Incremental(ProgramInput {
                    self_account_id,
                    caller_account_id,
                    pre_states,
                    instruction: instruction_data,
                }));
            };
            ProgramOutput::new(self_account_id, caller_account_id, instruction_data, vec![])
                .with_call_kind(CallKind::Incremental)
                .with_events(vec![ProgramEvent {
                    selector: DeferReads::SELECTOR,
                    data: DeferReads::All.to_bytes(),
                }])
                .write();
        }
        ProgramCall::Unsupported(..) | _ => respond_unsupported_call(call),
    }
}
