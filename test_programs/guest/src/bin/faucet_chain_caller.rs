use borsh::to_vec;
use lee_core::{
    account::{AccountDiff, AccountId},
    program::{
        AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};

type Instruction = (ProgramId, ProgramId, AccountId, u128);
// (faucet_program_id, vault_program_id, recipient_id, amount)

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (faucet_program_id, vault_program_id, recipient_id, amount),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountDiffOutput::new(AccountDiff::unchanged(pre.account_id)))
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

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
