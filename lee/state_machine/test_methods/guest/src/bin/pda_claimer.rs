use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = PdaSeed;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: seed,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => {
            unreachable!(
                "pda_claimer never produces an AccountDiffOutput with diff_data, so its \
                 UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };
    let account_post = AccountDiffOutput::new_claimed(diff, Claim::Pda(seed));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![account_post],
    )
    .write();
}
