use borsh::to_vec;
use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

type Instruction = (ProgramId, AccountId, AccountId, AccountId, u128);
// (faucet_program_id, faucet_account_id, vault_account_id, recipient_id, amount)

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction:
                (faucet_program_id, faucet_account_id, vault_account_id, recipient_id, amount),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    assert_eq!(pre_states.len(), 2);
    let [faucet_pre, vault_pda_pre] = [pre_states[0].clone(), pre_states[1].clone()];

    let chained_calls = vec![ChainedCall {
        program_account_id: faucet_account_id,
        instruction_data: to_vec(&faucet_core::Instruction::GenesisTransferVault {
            self_program_id: faucet_program_id,
            vault_account_id,
            recipient_id,
            amount,
        })
        .unwrap(),
        pre_states: vec![faucet_pre, vault_pda_pre],
        pda_seeds: vec![],
    }];

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
