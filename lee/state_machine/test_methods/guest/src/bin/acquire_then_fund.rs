use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// The amount to fund, the program that acquires the recipient, the program that funds it, and
/// the data the acquirer writes.
type Instruction = (u128, AccountId, AccountId, Vec<u8>);

/// Chains twice, in sequence: first to an acquirer that writes `data` into the recipient and so
/// takes it over, then to a plain transfer that funds it from the sender.
///
/// Accepts an optional third account, untouched by either call and echoed straight through, for
/// callers that need a padding account to satisfy the privacy-preserving transaction's "at least
/// one private action" precondition.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (balance, acquirer_id, transfer_id, data),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let (recipient_pre, sender_pre, padding_pre): (
        AccountWithMetadata,
        AccountWithMetadata,
        Option<AccountWithMetadata>,
    ) = match <[_; 3]>::try_from(pre_states) {
        Ok([recipient_pre, sender_pre, padding_pre]) => {
            (recipient_pre, sender_pre, Some(padding_pre))
        }
        Err(pre_states) => {
            let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
                return;
            };
            (recipient_pre, sender_pre, None)
        }
    };

    let acquire_call = ChainedCall::new(acquirer_id, vec![recipient_pre.account_id], &data);
    let fund_call = ChainedCall::new(
        transfer_id,
        vec![sender_pre.account_id, recipient_pre.account_id],
        &balance,
    );

    let state_diffs = [recipient_pre, sender_pre]
        .into_iter()
        .chain(padding_pre)
        .map(AccountStateDiff::unchanged)
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(vec![acquire_call, fund_call])
    .write();
}
