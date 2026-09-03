use authenticated_transfer_core::custody_transfer;
use faucet_core::Instruction;
use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

include!(concat!(
    env!("OUT_DIR"),
    "/authenticated_transfer_image_id.rs"
));

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: Instruction::GenesisTransfer { amount },
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "Faucet cannot be invoked through chain calls"
    );

    let post_states = pre_states.iter().map(|pre| pre.account.clone()).collect();
    let [faucet, recipient] = <[_; 2]>::try_from(pre_states.clone())
        .expect("GenesisTransfer requires exactly 2 accounts");

    assert_eq!(
        faucet.account_id,
        faucet_core::compute_faucet_account_id(self_program_id),
        "First account must be faucet PDA"
    );

    let transfer = custody_transfer(
        AUTHENTICATED_TRANSFER_IMAGE_ID,
        faucet,
        faucet_core::compute_faucet_seed(),
        recipient,
        amount,
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![transfer])
    .write();
}
