use nssa_core::program::{
    AccountPostState, Claim, PdaSeed, ProgramInput, ProgramOutput, read_nssa_inputs,
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
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre_a, pre_b]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let claim_a = AccountPostState::new_claimed(pre_a.account.clone(), Claim::Pda(seed));
    let claim_b = AccountPostState::new_claimed(pre_b.account.clone(), Claim::Pda(seed));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre_a, pre_b],
        vec![claim_a, claim_b],
    )
    .write();
}
