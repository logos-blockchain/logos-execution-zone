//! Forwards a single chained call to `target_program_id` with `instruction_data`, passing
//! through whatever `pre_states` this program itself was invoked with unchanged.
//!
//! Exists purely as test infrastructure: lets a test exercise "program X invokes program Y via
//! a chained call" for an arbitrary Y and instruction, without needing a purpose-built guest for
//! every target program under test.

use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput,
    read_lee_inputs,
};

type Instruction = (ProgramId, InstructionData);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (target_program_id, target_instruction_data),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    let chained_call = ChainedCall {
        program_account_id: target_program_id.into(),
        instruction_data: target_instruction_data,
        pre_state_ids: pre_states.iter().map(|pre| pre.account_id).collect(),
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
