use lee_core::{
    account::{AccountId, BalanceDiff},
    program::{
        AccountStateDiff, CallKind, DeferReads, IncrementalCall, ProgramCall, ProgramInput,
        ProgramOutput, read_lee_call, respond_probe, respond_unsupported_call,
    },
};

const WRONG_ACCOUNT: AccountId = AccountId::new([0xEE; 32]);

type Instruction = Vec<u8>;

/// An identity `Incremental` program, but its `Update` handler resolves a diff for a hardcoded,
/// unrelated account instead of the one it was actually asked about — exercises `resolve_write`'s
/// check that an `Update` resolution names the account it was given, not a different one.
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
            let [mut pre]: [_; 1] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("takes exactly one account"));
            pre.account_id = WRONG_ACCOUNT; // WRONG: should stay the account we were asked about
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
