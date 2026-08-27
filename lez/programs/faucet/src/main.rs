use faucet_core::Instruction;
use lee_core::program::{AccountDiffOutput, ChainedCall, ProgramCall, read_lee_call};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<Instruction>();
    let self_program_id = input.call.self_program_id;

    assert!(
        input.call.caller_program_id.is_none(),
        "Faucet cannot be invoked through chain calls"
    );

    let post_states = input
        .pre_states
        .iter()
        .map(|pre_state| AccountDiffOutput::unchanged(pre_state.account_id))
        .collect();

    let chained_calls = match instruction {
        Instruction::GenesisTransferVault {
            vault_program_id,
            recipient_id,
            amount,
        } => {
            let [faucet, recipient_vault] = input.pre_states.as_slice() else {
                panic!("Transfer requires exactly 2 accounts");
            };

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_program_id),
                "First account must be faucet PDA"
            );

            vec![
                ChainedCall::new(
                    vault_program_id,
                    vec![faucet.account_id, recipient_vault.account_id],
                    &vault_core::Instruction::Transfer {
                        recipient_id,
                        amount,
                    },
                )
                .with_pda_seeds(vec![faucet_core::compute_faucet_seed()]),
            ]
        }
        Instruction::GenesisTransferDirect { amount } => {
            let [faucet, recipient] = input.pre_states.as_slice() else {
                panic!("TransferDirect requires exactly 2 accounts");
            };

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_program_id),
                "First account must be faucet PDA"
            );

            vec![
                ChainedCall::new(
                    faucet.account.program_owner.into(),
                    vec![faucet.account_id, recipient.account_id],
                    &authenticated_transfer_core::Instruction::Transfer { amount },
                )
                .with_pda_seeds(vec![faucet_core::compute_faucet_seed()]),
            ]
        }
    };

    input
        .into_output(post_states)
        .with_chained_calls(chained_calls)
        .write();
}
