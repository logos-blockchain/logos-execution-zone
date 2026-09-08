use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

type Instruction = (u128, ProgramId, u32, Option<PdaSeed>);

/// A program that calls another program `num_chain_calls` times.
/// It permutes the order of the input accounts on the subsequent call
/// The `ProgramId` in the instruction must be the `program_id` of the authenticated transfers
/// program.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (balance, auth_transfer_id, num_chain_calls, pda_seed),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let call_instruction_data =
        to_vec(&AuthTransferInstruction::Transfer { amount: balance }).unwrap();

    let mut chained_calls = Vec::new();
    for _i in 0..num_chain_calls {
        let new_chained_call = ChainedCall {
            program_account_id: auth_transfer_id.into(),
            instruction_data: call_instruction_data.clone(),
            // Account order permuted here (sender before recipient).
            shard_selectors: vec![
                ProgramShardSelector::from(&sender_pre),
                ProgramShardSelector::from(&recipient_pre),
            ],
            pda_seeds: pda_seed.iter().copied().collect(),
        };
        chained_calls.push(new_chained_call);
    }

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::unchanged(sender_pre),
            AccountStateDiff::unchanged(recipient_pre),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
