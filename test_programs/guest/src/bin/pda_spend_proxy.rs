use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

/// Proxy for spending from a private PDA via `auth_transfer`.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `auth_transfer`.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount, auth_transfer_id),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let first_post = AccountStateDiff::unchanged(first.clone());
    let second_post = AccountStateDiff::unchanged(second.clone());

    let chained_call = ChainedCall {
        program_account_id: auth_transfer_id.into(),
        instruction_data: to_vec(&authenticated_transfer_core::Instruction::Transfer { amount })
            .unwrap(),
        shard_selectors: vec![
            ProgramShardSelector::from(&first),
            ProgramShardSelector::from(&second),
        ],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
