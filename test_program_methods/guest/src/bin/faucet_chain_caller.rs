use nssa_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_nssa_inputs,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (ProgramId, ProgramId, AccountId, u128);
// (faucet_program_id, vault_program_id, recipient_id, amount)

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (faucet_program_id, vault_program_id, recipient_id, amount),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    assert_eq!(pre_states.len(), 2);
    let [faucet_pre, vault_pda_pre] = [pre_states[0].clone(), pre_states[1].clone()];

    let chained_calls = vec![ChainedCall {
        program_id: faucet_program_id,
        instruction_data: to_vec(&faucet_core::Instruction::Transfer {
            vault_program_id,
            recipient_id,
            amount,
        })
        .unwrap(),
        pre_states: vec![faucet_pre, vault_pda_pre],
        pda_seeds: vec![],
    }];

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
