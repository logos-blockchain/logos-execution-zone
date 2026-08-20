use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (u128, ProgramId, u32, Option<PdaSeed>);

/// A program that calls another program `num_chain_calls` times.
/// It permutes the order of the input accounts on the subsequent call
/// The `ProgramId` in the instruction must be the `program_id` of the transfers
/// program.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (balance, simple_transfer_id, num_chain_calls, pda_seed),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "chain_caller program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let instruction_data = to_vec(&balance).unwrap();

    let mut chained_calls = Vec::new();
    for _i in 0..num_chain_calls {
        let new_chained_call = ChainedCall {
            program_id: simple_transfer_id,
            instruction_data: instruction_data.clone(),
            // Account order permuted here (sender before recipient), matching the callee's own
            // parameter order.
            pre_state_refs: vec![sender_pre.account_id, recipient_pre.account_id],
            pda_seeds: pda_seed.iter().copied().collect(),
        };
        chained_calls.push(new_chained_call);
    }

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender_pre.clone(), recipient_pre.clone()],
        vec![
            AccountDiffOutput::new(AccountDiff {
                id: sender_pre.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            }),
            AccountDiffOutput::new(AccountDiff {
                id: recipient_pre.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            }),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
