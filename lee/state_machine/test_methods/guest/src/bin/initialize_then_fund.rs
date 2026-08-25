use borsh::to_vec;
use lee_core::{
    account::AccountWithMetadata,
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

type Instruction = (u128, ProgramId, ProgramId);

/// Chains twice, in sequence: first to a bare claimer that initializes the recipient (claims it
/// with zero balance change), then to a plain transfer that funds it from the sender.
///
/// Accepts an optional third account, untouched by either call and echoed straight through — for
/// callers that need a padding account to satisfy the privacy-preserving transaction's "at least
/// one private action" precondition.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (balance, claimer_id, simple_transfer_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let (recipient_pre, sender_pre, padding_pre): (
        AccountWithMetadata,
        AccountWithMetadata,
        Option<AccountWithMetadata>,
    ) = if let Ok([recipient_pre, sender_pre, padding_pre]) =
        <[_; 3]>::try_from(pre_states.clone())
    {
        (recipient_pre, sender_pre, Some(padding_pre))
    } else {
        let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
            return;
        };
        (recipient_pre, sender_pre, None)
    };

    let initialize_call = ChainedCall {
        program_id: claimer_id,
        instruction_data: to_vec(&()).unwrap(),
        pre_state_refs: vec![recipient_pre.account_id],
        pda_seeds: vec![],
    };

    let fund_call = ChainedCall {
        program_id: simple_transfer_id,
        instruction_data: to_vec(&balance).unwrap(),
        pre_state_refs: vec![sender_pre.account_id, recipient_pre.account_id],
        pda_seeds: vec![],
    };

    let mut output_pre_states = vec![recipient_pre.clone(), sender_pre.clone()];
    let mut output_post_states = vec![
        AccountPostState::new(recipient_pre.account),
        AccountPostState::new(sender_pre.account),
    ];
    if let Some(padding_pre) = padding_pre {
        output_post_states.push(AccountPostState::new(padding_pre.account.clone()));
        output_pre_states.push(padding_pre);
    }

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        output_pre_states,
        output_post_states,
    )
    .with_chained_calls(vec![initialize_call, fund_call])
    .write();
}
