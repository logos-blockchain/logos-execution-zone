use faucet_core::Instruction;
use nssa_core::program::{
    AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_nssa_inputs,
};

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
            vault_program_id,
            recipient_id,
            amount,
        } => {
            let [faucet, recipient_vault] = pre_states
                .try_into()
                .expect("Transfer requires exactly 2 accounts");

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_program_id),
                "First account must be faucet PDA"
            );

            let mut faucet_for_vault = faucet;
            faucet_for_vault.is_authorized = true;

            vec![
                ChainedCall::new(
                    vault_program_id,
                    vec![faucet_for_vault, recipient_vault],
                    &vault_core::Instruction::Transfer {
                        recipient_id,
                        amount,
                    },
                )
                .with_pda_seeds(vec![faucet_core::compute_faucet_seed()]),
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
