use borsh::to_vec;
use lee_core::program::{
    ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

/// Chains to `callee_program_id`, delegating authorization over the sole `pre_state` with
/// `delegated_seed` in `pda_seeds`. When the seed derives that account under the private form
/// this exercises the caller-seeds authorization path in `validate_and_sync_states`; when it
/// does not, the callee's `pre_state` has no authorization source and the circuit must reject.
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

    let unchanged = pre.account.clone();

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
        vec![unchanged],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
