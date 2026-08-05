use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

/// Claims two `pre_states` under the same `seed`. Used to exercise the tx-wide
/// `(program_id, seed) → AccountId` family-binding check: when both `pre_states` are mask-3
/// with different npks, each `Claim::Pda(seed)` resolves to a different `AccountId` under the
/// same `(program, seed)` key, and the circuit must reject.
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
                "two_pda_claimer never produces an AccountDiffOutput with diff_data, so its \
                 UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let Ok([pre_a, pre_b]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let diff_a = AccountDiff {
        id: pre_a.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };
    let diff_b = AccountDiff {
        id: pre_b.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };
    let claim_a = AccountDiffOutput::new_claimed(diff_a, Claim::Pda(seed));
    let claim_b = AccountDiffOutput::new_claimed(diff_b, Claim::Pda(seed));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre_a, pre_b],
        vec![claim_a, claim_b],
    )
    .write();
}
