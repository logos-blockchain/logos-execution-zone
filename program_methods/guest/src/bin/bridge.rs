use bridge_core::Instruction;
use lee_core::program::{
    AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs,
};

fn unchanged_post_states(
    pre_states: &[lee_core::account::AccountWithMetadata],
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
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let pre_states_clone = pre_states.clone();
    let post_states = unchanged_post_states(&pre_states_clone);

    let chained_calls = match instruction {
        Instruction::Deposit {
            l1_deposit_op_id: _,
            vault_program_id,
            recipient_id,
            amount,
        } => {
            let [bridge, recipient_vault] = pre_states
                .try_into()
                .expect("Deposit requires exactly 2 accounts");

            assert_eq!(
                bridge.account_id,
                bridge_core::compute_bridge_account_id(self_program_id),
                "First account must be bridge PDA"
            );

            assert_eq!(
                recipient_vault.account_id,
                vault_core::compute_vault_account_id(vault_program_id, recipient_id),
                "Second account must be recipient vault PDA"
            );

            let mut bridge_for_vault = bridge;
            bridge_for_vault.is_authorized = true;

            vec![
                ChainedCall::new(
                    vault_program_id,
                    vec![bridge_for_vault, recipient_vault],
                    &vault_core::Instruction::Transfer {
                        recipient_id,
                        amount,
                    },
                )
                .with_pda_seeds(vec![bridge_core::compute_bridge_seed()]),
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
