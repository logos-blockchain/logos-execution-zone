use borsh::to_vec;
use lee_core::{
    account::{AccountId, BalanceDiff},
    program::{
        AccountStateDiff, ChainedCall, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call, respond_unsupported_call,
    },
};

/// Claims the sole `pre_state` as a PDA with `claim_seed`, then chains to `callee_account_id`
/// delegating authorization with `delegated_seed` in `pda_seeds`. When `claim_seed ==
/// delegated_seed` this exercises the happy caller-seeds authorization path for mask-3 private
/// PDAs; when they differ, the protocol resolves the callee's mask-3 `pre_state` as
/// unauthorized, and the callee itself must reject it. `callee_account_id` must be the
/// callee's dispatch address.
type Instruction = (PdaSeed, PdaSeed, AccountId);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (claim_seed, delegated_seed, callee_account_id),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let chained_call = ChainedCall {
        program_account_id: callee_account_id,
        instruction_data: to_vec(&()).unwrap(),
        pre_state_ids: vec![pre.account_id],
        pda_seeds: vec![delegated_seed],
    };

    let post_data = pre.account.data.clone();
    let claimed =
        AccountStateDiff::new_claimed(pre, BalanceDiff::Add(0), post_data, Claim::Pda(claim_seed));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![claimed],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
