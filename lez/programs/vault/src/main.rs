//! Vault program which allows users to create vault accounts and transfer funds to them.
//! Funds can later be claimed from the vault accounts by their owners.
//!
//! The program is designed to be used in conjunction with the authenticated transfer program, which
//! performs the actual transfer of funds from the vault accounts.

use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, ChainedCall, ProgramCall, read_lee_call},
};
use vault_core::Instruction;

fn unchanged_diffs(
    pre_states: &[lee_core::account::AccountWithMetadata],
) -> Vec<AccountDiffOutput> {
    pre_states
        .iter()
        .map(|pre_state| AccountDiffOutput::new(AccountDiff::unchanged(pre_state.account_id)))
        .collect()
}

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<Instruction>();
    let pre_states = input.pre_states.clone();

    let post_states = unchanged_diffs(&input.pre_states);

    let chained_calls = match instruction {
        Instruction::Transfer {
            recipient_id,
            amount,
        } => {
            let [sender, recipient_vault] = pre_states
                .try_into()
                .expect("Transfer requires exactly 2 accounts");

            let seed = vault_core::compute_vault_seed(recipient_id);

            vec![
                ChainedCall::new(
                    sender.account.program_owner.into(),
                    vec![sender.account_id, recipient_vault.account_id],
                    &AuthTransferInstruction::Transfer { amount },
                )
                .with_pda_seeds(vec![seed]),
            ]
        }
        Instruction::Claim { amount } => {
            let [owner, owner_vault] = pre_states
                .try_into()
                .expect("Claim requires exactly 2 accounts");

            assert!(
                owner.is_authorized,
                "Owner must be authorized to claim from the vault"
            );

            let seed = vault_core::compute_vault_seed(owner.account_id);

            vec![
                ChainedCall::new(
                    owner_vault.account.program_owner.into(),
                    vec![owner_vault.account_id, owner.account_id],
                    &AuthTransferInstruction::Transfer { amount },
                )
                .with_pda_seeds(vec![seed]),
            ]
        }
    };

    input
        .into_output(post_states)
        .with_chained_calls(chained_calls)
        .write();
}
