use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, Claim, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};
use risc0_zkvm::serde::to_vec;

/// Claims the sole `pre_state` as a PDA with `claim_seed`, then chains to `callee_program_id`
/// delegating authorization with `delegated_seed` in `pda_seeds`. When `claim_seed ==
/// delegated_seed` this exercises the happy caller-seeds authorization path for mask-3 private
/// PDAs in `validate_and_sync_states`; when they differ, the callee's mask-3 `pre_state` has
/// no matching authorization source and the circuit must reject.
type Instruction = (PdaSeed, PdaSeed, ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (claim_seed, delegated_seed, callee_program_id),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "private_pda_delegator program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let claimed = AccountDiffOutput::new_claimed(
        AccountDiff {
            id: pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        },
        Claim::Pda(claim_seed),
    );

    let chained_call = ChainedCall {
        program_id: callee_program_id,
        instruction_data: to_vec(&()).unwrap(),
        pre_state_refs: vec![pre.account_id],
        pda_seeds: vec![delegated_seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![claimed],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
