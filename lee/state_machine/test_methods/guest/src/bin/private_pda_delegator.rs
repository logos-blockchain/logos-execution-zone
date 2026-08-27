use borsh::to_vec;
use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, ChainedCall, Claim, PdaSeed, ProgramCall, ProgramId, read_lee_call,
    },
};

/// Claims the sole `pre_state` as a PDA with `claim_seed`, then chains to `callee_program_id`
/// delegating authorization with `delegated_seed` in `pda_seeds`. When `claim_seed ==
/// delegated_seed` this exercises the happy caller-seeds authorization path for mask-3 private
/// PDAs; when they differ, the protocol resolves the callee's mask-3 `pre_state` as
/// unauthorized, and the callee itself must reject it.
type Instruction = (PdaSeed, PdaSeed, ProgramId);

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (claim_seed, delegated_seed, callee_program_id),
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        return;
    };

    let claimed = AccountDiffOutput::new_claimed(
        AccountDiff::unchanged(pre.account_id),
        Claim::Pda(claim_seed),
    );

    let chained_call = ChainedCall {
        program_id: callee_program_id,
        instruction_data: to_vec(&()).unwrap(),
        accounts: vec![pre.account_id],
        pda_seeds: vec![delegated_seed],
    };

    input
        .into_output(vec![claimed])
        .with_chained_calls(vec![chained_call])
        .write();
}
