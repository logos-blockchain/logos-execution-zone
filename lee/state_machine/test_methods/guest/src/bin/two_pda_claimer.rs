use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Claims two `pre_states` under the same `seed`. Used to exercise the tx-wide
/// `(program_id, seed) → AccountId` family-binding check: when both `pre_states` are mask-3
/// with different npks, each `Claim::Pda(seed)` resolves to a different `AccountId` under the
/// same `(program, seed)` key, and the circuit must reject.
type Instruction = PdaSeed;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: seed,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre_a, pre_b]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let post_data_a = pre_a.account.data.clone();
    let post_data_b = pre_b.account.data.clone();
    let claim_a =
        AccountStateDiff::new_claimed(pre_a, BalanceDiff::Add(0), post_data_a, Claim::Pda(seed));
    let claim_b =
        AccountStateDiff::new_claimed(pre_b, BalanceDiff::Add(0), post_data_b, Claim::Pda(seed));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![claim_a, claim_b],
    )
    .write();
}
