use borsh::to_vec;
use lee_core::program::{
    AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
    read_lee_call, respond_unsupported_call,
};

/// Proxy for spending from a private PDA via `simple_transfer`.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `simple_transfer`.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount, simple_transfer_id),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let chained_call = ChainedCall {
        program_account_id: simple_transfer_id.into(),
        instruction_data: to_vec(&amount).unwrap(),
        pre_state_ids: vec![first.account_id, second.account_id],
        pda_seeds: vec![seed],
    };

    let first_post = AccountStateDiff::unchanged(first);
    let second_post = AccountStateDiff::unchanged(second);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
