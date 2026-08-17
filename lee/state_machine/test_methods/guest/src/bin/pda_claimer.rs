use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    },
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
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "pda_claimer program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_post = AccountDiffOutput::new_claimed(
        AccountDiff {
            id: pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        },
        Claim::Pda(seed),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![account_post],
    )
    .write();
}
