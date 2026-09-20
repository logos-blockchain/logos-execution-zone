use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, CallKind, DeferReads, IncrementalCall, ProgramCall, ProgramInput,
        ProgramOutput, read_lee_call, respond_probe, respond_unsupported_call,
    },
};

type Instruction = Vec<u8>;

/// Writes its first account (identity `Incremental`) and merely reads its second, unchanged.
/// Claims `DeferReads::WriteOnly` on `Probe`, which covers the write but not the read.
/// Exercises that an uncovered read forces `Bound`, independent of a covered write on a
/// different account in the same call.
fn main() {
    let call = read_lee_call::<Instruction>();
    match call {
        ProgramCall::Execute(
            ProgramInput {
                self_account_id,
                caller_account_id,
                pre_states,
                instruction,
            },
            instruction_data,
        ) => {
            let [written, read]: [_; 2] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("takes exactly two accounts"));
            let post_data = instruction
                .try_into()
                .expect("delta fits under the data limit");
            let write_diff = AccountStateDiff::new(written, BalanceDiff::Add(0), post_data);
            let read_diff = AccountStateDiff::unchanged(read);
            ProgramOutput::new(
                self_account_id,
                caller_account_id,
                instruction_data,
                vec![write_diff, read_diff],
            )
            .write();
        }
        ProgramCall::Probe(input) => {
            respond_probe(&input, Some(DeferReads::WriteOnly));
        }
        ProgramCall::Update(ProgramInput {
            self_account_id,
            pre_states,
            instruction: delta,
            ..
        }) => {
            let [pre]: [_; 1] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("takes exactly one account"));
            let post_data = delta
                .clone()
                .try_into()
                .expect("delta fits under the data limit");
            let diff = AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data);
            let instruction_data =
                borsh::to_vec(&IncrementalCall::Update(delta)).expect("IncrementalCall serializes");
            ProgramOutput::new(self_account_id, None, instruction_data, vec![diff])
                .with_call_kind(CallKind::Incremental)
                .write();
        }
        ProgramCall::Unsupported(..) | _ => respond_unsupported_call(call),
    }
}
