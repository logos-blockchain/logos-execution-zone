use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use borsh::to_vec;
use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, CallContext, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};

type Instruction = (u128, ProgramId, u32, Option<PdaSeed>);

/// A program that calls another program `num_chain_calls` times.
/// It permutes the order of the input accounts on the subsequent call
/// The `ProgramId` in the instruction must be the `program_id` of the authenticated transfers
/// program.
fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (balance, auth_transfer_id, num_chain_calls, pda_seed),
    } = read_lee_call::<Instruction>();
    let ProgramInput {
        call:
            CallContext {
                self_program_id,
                caller_program_id,
                instruction_data,
            },
        pre_states,
    } = input;

    let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let call_instruction_data =
        to_vec(&AuthTransferInstruction::Transfer { amount: balance }).unwrap();

    let mut chained_calls = Vec::new();
    for _i in 0..num_chain_calls {
        let new_chained_call = ChainedCall {
            program_id: auth_transfer_id,
            instruction_data: call_instruction_data.clone(),
            // Account order permuted here (sender before recipient).
            accounts: vec![sender_pre.account_id, recipient_pre.account_id],
            pda_seeds: pda_seed.iter().copied().collect(),
        };
        chained_calls.push(new_chained_call);
    }

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![sender_pre.clone(), recipient_pre.clone()],
        vec![
            AccountDiffOutput::new(AccountDiff::unchanged(sender_pre.account_id)),
            AccountDiffOutput::new(AccountDiff::unchanged(recipient_pre.account_id)),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
