use borsh::to_vec;
use lee_core::{
    account::AccountId,
    program::{AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, read_lee_call},
};

type Instruction = (ProgramId, ProgramId, AccountId, u128);
// (faucet_program_id, vault_program_id, recipient_id, amount)

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (faucet_program_id, vault_program_id, recipient_id, amount),
    } = read_lee_call::<Instruction>();
    let pre_states = &input.pre_states;

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountDiffOutput::unchanged(pre.account_id))
        .collect();

    assert_eq!(pre_states.len(), 2);

    let chained_calls = vec![ChainedCall {
        program_id: faucet_program_id,
        instruction_data: to_vec(&faucet_core::Instruction::GenesisTransferVault {
            vault_program_id,
            recipient_id,
            amount,
        })
        .unwrap(),
        accounts: vec![pre_states[0].account_id, pre_states[1].account_id],
        pda_seeds: vec![],
    }];

    input
        .into_output(post_states)
        .with_chained_calls(chained_calls)
        .write();
}
