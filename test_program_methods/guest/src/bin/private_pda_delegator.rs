use nssa_core::program::{
    AccountPostState, ChainedCall, Claim, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
    read_nssa_inputs,
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
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let claimed = AccountPostState::new_claimed(pre.account.clone(), Claim::Pda(claim_seed));

    let mut pre_for_callee = pre.clone();
    pre_for_callee.is_authorized = true;
    pre_for_callee.account.program_owner = self_program_id;

    let chained_call = ChainedCall {
        program_id: callee_program_id,
        instruction_data: to_vec(&()).unwrap(),
        pre_states: vec![pre_for_callee],
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
