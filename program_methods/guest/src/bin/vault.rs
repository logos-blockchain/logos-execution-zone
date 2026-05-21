//! Vault program which allows users to create vault accounts and transfer funds to them.
//! Funds can later be claimed from the vault accounts by their owners.
//!
//! The program is designed to be used in conjunction with the authenticated transfer program, which
//! performs the actual transfer of funds from the vault accounts.

use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use nssa_core::program::{
    AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_nssa_inputs,
};
use vault_core::Instruction;

fn unchanged_post_states(
    pre_states: &[nssa_core::account::AccountWithMetadata],
) -> Vec<AccountPostState> {
    pre_states
        .iter()
        .map(|pre_state| AccountPostState::new(pre_state.account.clone()))
        .collect()
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let pre_states_clone = pre_states.clone();
    let post_states = unchanged_post_states(&pre_states_clone);

    let chained_calls = match instruction {
        Instruction::Transfer {
            recipient_id,
            amount,
        } => {
            let [sender, recipient_vault] = pre_states
                .try_into()
                .expect("Transfer requires exactly 2 accounts");

            let seed = vault_core::compute_vault_seed(recipient_id);

            let mut recipient_vault_for_callee = recipient_vault;
            recipient_vault_for_callee.is_authorized = true;

            vec![
                ChainedCall::new(
                    sender.account.program_owner,
                    vec![sender, recipient_vault_for_callee],
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

            let mut owner_vault_for_callee = owner_vault;
            owner_vault_for_callee.is_authorized = true;

            vec![
                ChainedCall::new(
                    owner_vault_for_callee.account.program_owner,
                    vec![owner_vault_for_callee, owner],
                    &AuthTransferInstruction::Transfer { amount },
                )
                .with_pda_seeds(vec![seed]),
            ]
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states_clone,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
