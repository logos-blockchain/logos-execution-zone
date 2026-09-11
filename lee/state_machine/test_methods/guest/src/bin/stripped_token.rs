use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, CallKind, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// The resolved, on-chain shape of a token account: no mint/definition, just a balance.
#[derive(BorshSerialize, BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

/// A delta to a token account's balance, carried as `post_data` in `Execute`'s output —
/// `Account.data` has no protocol-level delta mechanism, so this program defines its own, the
/// way `BalanceDiff` does for `Account.balance`.
#[derive(BorshSerialize, BorshDeserialize)]
enum TokenDiff {
    Add(u128),
    Sub(u128),
}

#[derive(BorshSerialize, BorshDeserialize)]
enum Instruction {
    /// Sets the account's token balance directly, with no ownership/access check — a test-only
    /// backdoor for seeding state, not something a real token program would expose.
    Initialize { balance: u128 },
    /// Moves `amount` from the first `pre_state`'s token balance to the second's.
    Transfer { amount: u128 },
}

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
            // Neither arm reads `pre_state.data`, so the diff never depends on which `pre_state`
            // it's applied against — insufficient-balance enforcement belongs to `Incremental`
            // instead, the only place that sees the real current balance.
            let state_diffs = match instruction {
                Instruction::Initialize { balance } => {
                    let [pre]: [_; 1] = pre_states
                        .try_into()
                        .unwrap_or_else(|_| panic!("Initialize takes exactly one account"));
                    let post_data = borsh::to_vec(&TokenDiff::Add(balance))
                        .expect("token diff serializes")
                        .try_into()
                        .expect("token diff fits under the size limit");
                    vec![AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data)]
                }
                Instruction::Transfer { amount } => {
                    let [sender_pre, receiver_pre]: [_; 2] = pre_states
                        .try_into()
                        .unwrap_or_else(|_| panic!("Transfer takes exactly two accounts"));

                    let sender_diff = AccountStateDiff::new(
                        sender_pre,
                        BalanceDiff::Add(0),
                        borsh::to_vec(&TokenDiff::Sub(amount))
                            .expect("token diff serializes")
                            .try_into()
                            .expect("token diff fits under the size limit"),
                    );
                    let receiver_diff = AccountStateDiff::new(
                        receiver_pre,
                        BalanceDiff::Add(0),
                        borsh::to_vec(&TokenDiff::Add(amount))
                            .expect("token diff serializes")
                            .try_into()
                            .expect("token diff fits under the size limit"),
                    );
                    vec![sender_diff, receiver_diff]
                }
            };

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
            let diff: TokenDiff = borsh::from_slice(&instruction_data)
                .expect("Incremental instruction must decode as TokenDiff");
            let [pre]: [_; 1] = pre_states
                .try_into()
                .unwrap_or_else(|_| panic!("Incremental takes exactly one account"));

            // Empty data means a fresh account nothing has ever initialized — treat it as
            // starting from a zero balance rather than failing to decode.
            let current_balance = if pre.account.data.is_empty() {
                0
            } else {
                let data: TokenAccountData = borsh::from_slice(&pre.account.data)
                    .expect("pre_state data must decode as TokenAccountData");
                data.balance
            };
            let new_balance = match diff {
                TokenDiff::Add(amount) => current_balance
                    .checked_add(amount)
                    .expect("token balance overflow"),
                TokenDiff::Sub(amount) => current_balance
                    .checked_sub(amount)
                    .expect("insufficient token balance"),
            };
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
