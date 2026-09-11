use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, CallKind, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = u128;

/// A balance-transfer delta, `Incremental`'s own instruction shape — direction-tagged because
/// `Incremental` resolves one account at a time, with no sender/receiver role to infer it from.
#[derive(BorshSerialize, BorshDeserialize)]
enum BalanceTransferDelta {
    Add(u128),
    Sub(u128),
}

/// `simple_balance_transfer`'s twin, opted into `Incremental`. `BalanceDiff` already composes
/// safely against any `pre_state`, so `Execute` moves `amount` directly and never touches
/// `data` — meaning `Incremental` is never actually reached through `resolve_diff` here, only
/// by a caller that dispatches it directly.
fn main() {
    let call = read_lee_call::<Instruction>();
    match call {
        ProgramCall::Execute(
            ProgramInput {
                self_account_id,
                caller_account_id,
                pre_states,
                instruction: amount,
            },
            instruction_data,
        ) => {
            let [sender_pre, receiver_pre]: [_; 2] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("Transfer takes exactly two accounts"));

            let sender_post_data = sender_pre.account.data.clone();
            let receiver_post_data = receiver_pre.account.data.clone();

            let sender_diff =
                AccountStateDiff::new(sender_pre, BalanceDiff::Sub(amount), sender_post_data);
            let receiver_diff =
                AccountStateDiff::new(receiver_pre, BalanceDiff::Add(amount), receiver_post_data);

            ProgramOutput::new(
                self_account_id,
                caller_account_id,
                instruction_data,
                vec![sender_diff, receiver_diff],
            )
            .write();
        }
        ProgramCall::Incremental(ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: instruction_data,
        }) => {
            let delta: BalanceTransferDelta = borsh::from_slice(&instruction_data)
                .expect("Incremental instruction must decode as BalanceTransferDelta");
            let [pre]: [_; 1] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("Incremental takes exactly one account"));

            let balance_diff = match delta {
                BalanceTransferDelta::Add(amount) => BalanceDiff::Add(amount),
                BalanceTransferDelta::Sub(amount) => BalanceDiff::Sub(amount),
            };
            let post_data = pre.account.data.clone();
            let diff_output = AccountStateDiff::new(pre, balance_diff, post_data);

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
