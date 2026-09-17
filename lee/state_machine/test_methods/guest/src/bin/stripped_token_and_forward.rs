use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, BalanceDiff},
    program::{
        AccountStateDiff, CallKind, ChainedCall, DeferReads, IncrementalCall, InstructionData,
        ProgramCall, ProgramEvent, ProgramInput, ProgramOutput, read_lee_call, respond_probe,
        respond_unsupported_call,
    },
};

#[derive(BorshSerialize, BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum TokenDiff {
    Add(u128),
}

/// What this program's `Probe` response asserts.
#[derive(BorshSerialize, BorshDeserialize)]
enum ProbeAssertion {
    None,
    Real(DeferReads),
    Unrelated,
}

/// A made-up event, unrelated to `DeferReads`.
struct UnrelatedEvent;

impl UnrelatedEvent {
    const SELECTOR: [u8; 8] = [0x17, 0x01, 0xd5, 0xc8, 0xb9, 0xb9, 0x2e, 0xa5];
}

/// Raw bytes to write as `post_data`, the callee to forward the account to, the callee's
/// instruction, and what this program's `Probe` response should assert. `Execute` also accepts
/// an optional second, padding account (see `main`'s `Execute` arm).
type Instruction = (Vec<u8>, AccountId, InstructionData, ProbeAssertion);

/// `stripped_token`'s `Initialize`/`Incremental`, plus a forward on the same account — lets
/// tests chain a further touch onto an `Incremental`-eligible one, which `stripped_token` alone
/// can't do.
fn main() {
    let call = read_lee_call::<Instruction>();
    match call {
        ProgramCall::Execute(
            ProgramInput {
                self_account_id,
                caller_account_id,
                pre_states,
                instruction: (post_data_bytes, callee, callee_instruction, _probe_assertion),
            },
            instruction_data,
        ) => {
            // Accepts an optional second account, untouched and echoed straight through, for
            // callers that need a padding account to satisfy the privacy-preserving
            // transaction's "at least one private action" precondition.
            let (target, padding) = match <[_; 2]>::try_from(pre_states) {
                Ok([target, padding]) => (target, Some(padding)),
                Err(pre_states) => {
                    let Ok([target]) = <[_; 1]>::try_from(pre_states) else {
                        return;
                    };
                    (target, None)
                }
            };
            let account_id = target.account_id;

            let post_data = post_data_bytes
                .try_into()
                .expect("post data fits under the size limit");
            let target_diff = AccountStateDiff::new(target, BalanceDiff::Add(0), post_data);

            let chained_call = ChainedCall {
                program_account_id: callee,
                instruction_data: callee_instruction,
                pre_state_ids: vec![account_id],
                pda_seeds: vec![],
            };

            let state_diffs = core::iter::once(target_diff)
                .chain(padding.map(AccountStateDiff::unchanged))
                .collect();

            ProgramOutput::new(
                self_account_id,
                caller_account_id,
                instruction_data,
                state_diffs,
            )
            .with_chained_calls(vec![chained_call])
            .write();
        }
        ProgramCall::Probe(input) => {
            match &input.instruction.3 {
                ProbeAssertion::None => respond_probe(&input, None),
                ProbeAssertion::Real(claim) => {
                    let claim = *claim;
                    respond_probe(&input, Some(claim));
                }
                // A made-up event unrelated to `DeferReads` - `respond_probe` only ever emits a
                // `DeferReads` event (or none), so this case is built manually.
                ProbeAssertion::Unrelated => {
                    let instruction_data = borsh::to_vec(&IncrementalCall::Probe(
                        borsh::to_vec(&input.instruction).expect("instruction serializes"),
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
                        selector: UnrelatedEvent::SELECTOR,
                        data: Vec::new(),
                    }])
                    .write();
                }
            }
        }
        ProgramCall::Update(ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: delta_bytes,
        }) => {
            let Ok(TokenDiff::Add(amount)) = borsh::from_slice(&delta_bytes) else {
                respond_unsupported_call(ProgramCall::<Instruction>::Update(ProgramInput {
                    self_account_id,
                    caller_account_id,
                    pre_states,
                    instruction: delta_bytes,
                }));
            };
            let [pre]: [_; 1] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("Incremental takes exactly one account"));

            let current_balance = if pre.account.data.is_empty() {
                0
            } else {
                let data: TokenAccountData = borsh::from_slice(&pre.account.data)
                    .expect("pre_state data must decode as TokenAccountData");
                data.balance
            };
            let new_balance = current_balance
                .checked_add(amount)
                .expect("token balance overflow");
            let post_data = borsh::to_vec(&TokenAccountData {
                balance: new_balance,
            })
            .expect("token account data serializes")
            .try_into()
            .expect("token account data fits under the size limit");
            let diff_output = AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data);

            let instruction_data = borsh::to_vec(&IncrementalCall::Update(delta_bytes))
                .expect("IncrementalCall serializes");
            ProgramOutput::new(
                self_account_id,
                caller_account_id,
                instruction_data,
                vec![diff_output],
            )
            .with_call_kind(CallKind::Incremental)
            .write();
        }
        ProgramCall::Unsupported(..) | _ => respond_unsupported_call(call),
    }
}
