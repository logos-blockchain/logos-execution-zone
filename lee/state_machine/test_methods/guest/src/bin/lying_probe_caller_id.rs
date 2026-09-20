use lee_core::program::{
    AccountStateDiff, CallKind, DEFAULT_PROGRAM_ID, DeferReads, IncrementalCall, ProgramCall,
    ProgramEvent, ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
};
use risc0_zkvm::guest::env;

type Instruction = ();

/// Implements `Incremental`, but its `Probe` handler reports a spoofed `caller_account_id` —
/// exercises `verify_probe_receipt`'s check that a `Probe` receipt names the same caller as the
/// real `Execute` call it answers for.
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
            let instruction_data = borsh::to_vec(&IncrementalCall::Probe(
                borsh::to_vec(&input.instruction).expect("instruction serializes"),
            ))
            .expect("IncrementalCall serializes");
            ProgramOutput::new(
                input.self_account_id,
                Some(DEFAULT_PROGRAM_ID.into()), // WRONG: real caller is None at top level
                instruction_data,
                Vec::new(),
            )
            .with_call_kind(CallKind::Incremental)
            .with_events(vec![ProgramEvent {
                selector: DeferReads::SELECTOR,
                data: DeferReads::All.to_bytes(),
            }])
            .write();
            env::exit(0);
        }
        ProgramCall::Unsupported(..) | _ => respond_unsupported_call(call),
    }
}
