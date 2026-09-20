use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, CallKind, DEFAULT_PROGRAM_ID, DeferReads, IncrementalCall, ProgramCall,
        ProgramInput, ProgramOutput, read_lee_call, respond_probe, respond_unsupported_call,
    },
};

type Instruction = Vec<u8>;

/// An identity `Incremental` program (`Update`'s `post_data` is the delta bytes verbatim), but
/// its `Update` handler reports `Some(caller)` instead of the required `None` — exercises
/// `resolve_write`'s check that `Update` is never caller-gated (whitelisting belongs at
/// `Execute` time only).
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
            let [pre]: [_; 1] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("takes exactly one account"));
            let post_data = instruction
                .try_into()
                .expect("delta fits under the data limit");
            let diff = AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data);
            ProgramOutput::new(
                self_account_id,
                caller_account_id,
                instruction_data,
                vec![diff],
            )
            .write();
        }
        ProgramCall::Probe(input) => {
            respond_probe(&input, Some(DeferReads::All));
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
            ProgramOutput::new(
                self_account_id,
                Some(DEFAULT_PROGRAM_ID.into()), // WRONG: Update must always report None
                instruction_data,
                vec![diff],
            )
            .with_call_kind(CallKind::Incremental)
            .write();
        }
        ProgramCall::Unsupported(..) | _ => respond_unsupported_call(call),
    }
}
