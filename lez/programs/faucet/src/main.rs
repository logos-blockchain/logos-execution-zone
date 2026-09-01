use faucet_core::Instruction;
use lee_core::{
    account::Account,
    program::{ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs},
};

include!("../../authenticated_transfer/image_id.rs");

fn unchanged_post_states(pre_states: &[lee_core::account::AccountWithMetadata]) -> Vec<Account> {
    pre_states
        .iter()
        .map(|pre_state| pre_state.account.clone())
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
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "Faucet cannot be invoked through chain calls"
    );

    let pre_states_clone = pre_states.clone();
    let post_states = unchanged_post_states(&pre_states_clone);

    let chained_calls = match instruction {
        Instruction::GenesisTransfer { amount } => {
            let [faucet, recipient] = pre_states
                .try_into()
                .expect("GenesisTransfer requires exactly 2 accounts");

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_program_id),
                "First account must be faucet PDA"
            );

            let mut faucet_for_transfer = faucet;
            faucet_for_transfer.is_authorized = true;

            vec![
                ChainedCall::new(
                    AUTHENTICATED_TRANSFER_IMAGE_ID,
                    vec![faucet_for_transfer, recipient],
                    &authenticated_transfer_core::Instruction::Transfer { amount },
                )
                .with_pda_seeds(vec![faucet_core::compute_faucet_seed()]),
            ]
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states_clone,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
