//! Forwards a single chained call to `target_program_id`'s dispatch address with
//! `instruction_data`, passing through whatever `pre_states` this program itself was invoked
//! with unchanged.
//!
//! Exists purely as test infrastructure: lets a test exercise "program X invokes program Y via
//! a chained call" for an arbitrary Y and instruction, without needing a purpose-built guest for
//! every target program under test.

use lee_core::{
    account::AccountId,
    program::{AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs},
};

type Instruction = (AccountId, Vec<u32>);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (target_program_id, instruction_data),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    let chained_call = ChainedCall {
        program_account_id: target_program_id,
        instruction_data,
        pre_states: pre_states.clone(),
        pda_seeds: vec![],
        raw_payload: None,
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
