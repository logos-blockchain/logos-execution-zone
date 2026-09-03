use borsh::to_vec;
use lee_core::{
    account::AccountId,
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = (AccountId, AccountId, AccountId, u128);
// (faucet_account_id, vault_account_id, recipient_id, amount)

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (faucet_account_id, vault_account_id, recipient_id, amount),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountStateDiff::unchanged(pre.clone()))
        .collect();

    assert_eq!(pre_states.len(), 2);
    let [faucet_pre, vault_pda_pre] = [pre_states[0].clone(), pre_states[1].clone()];

    let chained_calls = vec![ChainedCall {
        program_account_id: faucet_account_id,
        instruction_data: to_vec(&faucet_core::Instruction::GenesisTransferVault {
            vault_account_id,
            recipient_id,
            amount,
        })
        .unwrap(),
        pre_state_ids: vec![faucet_pre.account_id, vault_pda_pre.account_id],
        pda_seeds: vec![],
    }];

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
