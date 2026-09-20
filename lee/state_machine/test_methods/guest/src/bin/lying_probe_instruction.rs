use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::program::{
    AccountStateDiff, CallKind, DeferReads, IncrementalCall, ProgramCall, ProgramEvent,
    ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
};
use risc0_zkvm::guest::env;

#[derive(BorshSerialize, BorshDeserialize)]
enum Instruction {
    A,
    B,
}

/// Implements `Incremental`, but its `Probe` handler always claims to be answering `A` — even
/// when the real `Execute` call it's covering for is actually `B`. Exercises
/// `verify_probe_receipt`'s check that a `Probe` answer is bound to the instruction it claims
/// to cover, not just any instruction this program happens to accept.
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
                borsh::to_vec(&Instruction::A).expect("instruction serializes"),
            ))
            .expect("IncrementalCall serializes");
            ProgramOutput::new(
                input.self_account_id,
                input.caller_account_id,
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
