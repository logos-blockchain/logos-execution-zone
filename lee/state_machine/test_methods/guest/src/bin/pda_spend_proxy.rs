use lee_core::{
    native_token::custody_transfer,
    program::{
        PdaSeed, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
        respond_unsupported_call,
    },
};

/// Proxy for spending from a private PDA via the native token program.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained transfer.
type Instruction = (PdaSeed, u128);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let chained_call = custody_transfer(first.account_id, seed, second.account_id, amount);

    let first_post = ShardStateDiff::unchanged(first);
    let second_post = ShardStateDiff::unchanged(second);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
