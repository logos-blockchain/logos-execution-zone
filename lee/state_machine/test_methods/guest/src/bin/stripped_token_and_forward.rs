use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, CallKind, ChainedCall, InstructionData, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
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

/// Raw `post_data` to write (a caller-supplied `TokenDiff::Add` encoding resolves via
/// `Incremental` below; anything else — e.g. a bare `TokenAccountData` encoding — fails to
/// decode as `TokenDiff` and is gracefully declined as `Unsupported`, letting a test force this
/// account `Bound` without a second, differently-behaved program), the callee to forward the
/// same account to next, and the callee's instruction.
type Instruction = (Vec<u8>, ProgramId, InstructionData);

/// `stripped_token`'s `Initialize`/`Incremental`, plus a forward on the same account — lets
/// tests compose an `Incremental`-eligible touch with a further chained touch on the same
/// account, which `stripped_token` alone can't do (it never chains). Declining to decode
/// unrecognized `post_data` as `Unsupported` (rather than panicking) also lets one test drive
/// both a `Bound`-forcing touch and a genuinely-`Incremental` one from this same program —
/// ownership rules forbid a *different* program from touching an already-owned account, so
/// that's otherwise unreachable.
fn main() {
    let call = read_lee_call::<Instruction>();
    match call {
        ProgramCall::Execute(
            ProgramInput {
                self_account_id,
                caller_account_id,
                pre_states,
                instruction: (post_data_bytes, callee, callee_instruction),
            },
            instruction_data,
        ) => {
            let Ok([target]) = <[_; 1]>::try_from(pre_states) else {
                return;
            };
            let account_id = target.account_id;

            let post_data = post_data_bytes
                .try_into()
                .expect("post data fits under the size limit");
            let target_diff = AccountStateDiff::new(target, BalanceDiff::Add(0), post_data);

            let chained_call = ChainedCall {
                program_account_id: callee.into(),
                instruction_data: callee_instruction,
                pre_state_ids: vec![account_id],
                pda_seeds: vec![],
            };

            ProgramOutput::new(
                self_account_id,
                caller_account_id,
                instruction_data,
                vec![target_diff],
            )
            .with_chained_calls(vec![chained_call])
            .write();
        }
        ProgramCall::Incremental(ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: instruction_data,
        }) => {
            let Ok(TokenDiff::Add(amount)) = borsh::from_slice(&instruction_data) else {
                respond_unsupported_call(ProgramCall::<Instruction>::Incremental(ProgramInput {
                    self_account_id,
                    caller_account_id,
                    pre_states,
                    instruction: instruction_data,
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
