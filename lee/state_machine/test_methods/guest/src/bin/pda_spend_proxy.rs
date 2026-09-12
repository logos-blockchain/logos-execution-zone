use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    native_token::Instruction as NativeInstruction,
    program::{
        AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

/// Proxy for spending from a private PDA via the native token program.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained transfer.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount, transfer_program_id),
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
        program_account_id: transfer_program_id.into(),
        instruction_data: to_vec(&NativeInstruction::Transfer { amount }).unwrap(),
        shard_selectors: vec![
            ProgramShardSelector::from(&first),
            ProgramShardSelector::from(&second),
        ],
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
