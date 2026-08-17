use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, InstructionData, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};

type Instruction = (ProgramId, InstructionData, bool);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, declare_pre_states),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "non_delegating_forwarder program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let (output_pre_states, output_post_states) = if declare_pre_states {
        let post_states = pre_states
            .iter()
            .map(|account| {
                AccountDiffOutput::new(AccountDiff {
                    id: account.account_id,
                    diff_balance: BalanceDiff::Add(0),
                    diff_data: None,
                })
            })
            .collect();
        (pre_states.clone(), post_states)
    } else {
        (Vec::new(), Vec::new())
    };

    // Make exactly one chained call based on the input instruction with no
    // pda seeds, ensuring the target PDAs are never authorized.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        output_pre_states,
        output_post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_states,
        pda_seeds: vec![],
    }])
    .write();
}
