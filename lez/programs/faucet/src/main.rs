use faucet_core::Instruction;
use lee_core::program::{
    AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
};

fn unchanged_post_diffs(
    pre_states: &[lee_core::account::AccountWithMetadata],
) -> Vec<AccountStateDiff> {
    pre_states
        .iter()
        .map(|pre_state| AccountStateDiff::unchanged(pre_state.clone()))
        .collect()
}

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    assert!(
        caller_account_id.is_none(),
        "Faucet cannot be invoked through chain calls"
    );

    let pre_states_clone = pre_states.clone();
    let post_diffs = unchanged_post_diffs(&pre_states_clone);

    let chained_calls = match instruction {
        Instruction::GenesisTransferVault {
            vault_account_id,
            recipient_id,
            amount,
        } => {
            let [faucet, recipient_vault] = pre_states
                .try_into()
                .expect("Transfer requires exactly 2 accounts");

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_account_id),
                "First account must be faucet PDA"
            );

            let mut faucet_for_vault = faucet;
            faucet_for_vault.is_authorized = true;

            vec![
                ChainedCall::new(
                    vault_account_id,
                    vec![faucet_for_vault.account_id, recipient_vault.account_id],
                    &vault_core::Instruction::Transfer {
                        recipient_id,
                        amount,
                    },
                )
                .with_pda_seeds(vec![faucet_core::compute_faucet_seed()]),
            ]
        }
        Instruction::GenesisTransferDirect { amount } => {
            let [faucet, recipient] = pre_states
                .try_into()
                .expect("TransferDirect requires exactly 2 accounts");

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_account_id),
                "First account must be faucet PDA"
            );

            let mut faucet_for_transfer = faucet;
            faucet_for_transfer.is_authorized = true;

            vec![
                ChainedCall::new(
                    faucet_for_transfer.account.program_owner,
                    vec![faucet_for_transfer.account_id, recipient.account_id],
                    &authenticated_transfer_core::Instruction::Transfer { amount },
                )
                .with_pda_seeds(vec![faucet_core::compute_faucet_seed()]),
            ]
        }
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
