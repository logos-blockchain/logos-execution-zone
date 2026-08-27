use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, Claim, PdaSeed, ProgramCall, read_lee_call},
};

/// Claims two `pre_states` under the same `seed`. Used to exercise the tx-wide
/// `(program_id, seed) → AccountId` family-binding check: when both `pre_states` are mask-3
/// with different npks, each `Claim::Pda(seed)` resolves to a different `AccountId` under the
/// same `(program, seed)` key, and the circuit must reject.
type Instruction = PdaSeed;

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: seed,
    } = read_lee_call::<Instruction>();

    let [pre_a, pre_b] = input.pre_states.as_slice() else {
        return;
    };

    let claim_a =
        AccountDiffOutput::new_claimed(AccountDiff::unchanged(pre_a.account_id), Claim::Pda(seed));
    let claim_b =
        AccountDiffOutput::new_claimed(AccountDiff::unchanged(pre_b.account_id), Claim::Pda(seed));

    input.into_output(vec![claim_a, claim_b]).write();
}
