use borsh::to_vec;
use lee_core::program::{AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, read_lee_call};

type Instruction = (u128, ProgramId, ProgramId);

/// Chains twice, in sequence: first to a bare claimer that initializes the recipient (claims it
/// with zero balance change), then to a plain transfer that funds it from the sender.
///
/// Accepts an optional third account, untouched by either call and echoed straight through — for
/// callers that need a padding account to satisfy the privacy-preserving transaction's "at least
/// one private action" precondition.
fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (balance, claimer_id, simple_transfer_id),
    } = read_lee_call::<Instruction>();

    let (recipient_id, sender_id, padding_id) = match input.pre_states.as_slice() {
        [recipient_pre, sender_pre] => (recipient_pre.account_id, sender_pre.account_id, None),
        [recipient_pre, sender_pre, padding_pre] => (
            recipient_pre.account_id,
            sender_pre.account_id,
            Some(padding_pre.account_id),
        ),
        _ => return,
    };

    let initialize_call = ChainedCall {
        program_id: claimer_id,
        instruction_data: to_vec(&()).unwrap(),
        accounts: vec![recipient_id],
        pda_seeds: vec![],
    };

    let fund_call = ChainedCall {
        program_id: simple_transfer_id,
        instruction_data: to_vec(&balance).unwrap(),
        accounts: vec![sender_id, recipient_id],
        pda_seeds: vec![],
    };

    let mut post_states = vec![
        AccountDiffOutput::unchanged(recipient_id),
        AccountDiffOutput::unchanged(sender_id),
    ];
    if let Some(padding_id) = padding_id {
        post_states.push(AccountDiffOutput::unchanged(padding_id));
    }

    input
        .into_output(post_states)
        .with_chained_calls(vec![initialize_call, fund_call])
        .write();
}
