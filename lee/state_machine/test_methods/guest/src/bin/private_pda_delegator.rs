use borsh::to_vec;
use lee_core::program::{
    ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

/// Echoes the sole `pre_state` and chains to `callee_program_id`, delegating authorization with
/// `delegated_seed` in `pda_seeds`. When `delegated_seed` is the seed the account was derived
/// under, this exercises the happy caller-seeds authorization path for private PDAs in
/// `validate_and_sync_states` -- which is also what binds the position's npk. When it differs,
/// the callee's `pre_state` has no matching authorization source and the circuit must reject.
type Instruction = (PdaSeed, ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (delegated_seed, callee_program_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let post = pre.account.clone();

    let mut pre_for_callee = pre.clone();
    pre_for_callee.is_authorized = true;

    let chained_call = ChainedCall {
        program_id: callee_program_id,
        instruction_data: to_vec(&()).unwrap(),
        pre_states: vec![pre_for_callee],
        pda_seeds: vec![delegated_seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
