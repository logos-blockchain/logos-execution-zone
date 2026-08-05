use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, DEFAULT_PROGRAM_ID, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id: _, // ignore the correct ID
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => {
            unreachable!(
                "malicious_self_program_id never produces an AccountDiffOutput with diff_data, \
                 so its UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let diffs = pre_states
        .iter()
        .map(|a| {
            AccountDiffOutput::new(AccountDiff {
                id: a.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            })
        })
        .collect();

    // Deliberately output wrong self_program_id
    ProgramOutput::new(
        DEFAULT_PROGRAM_ID, // WRONG: should be self_program_id
        caller_program_id,
        instruction_words,
        pre_states,
        diffs,
    )
    .write();
}
