use faucet_core::Instruction;
use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

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

    let post_states = match instruction {
        Instruction::GenesisTransferDirect { amount } => {
            let [faucet, recipient] = <[_; 2]>::try_from(pre_states.clone())
                .expect("TransferDirect requires exactly 2 accounts");

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_program_id),
                "First account must be faucet PDA"
            );

            let mut faucet_post = faucet.into_slot_of(self_program_id);
            faucet_post.balance = faucet_post
                .balance
                .checked_sub(amount)
                .expect("Faucet has insufficient balance");

            let mut recipient_post = recipient.into_caller_named_slot();
            recipient_post.balance = recipient_post
                .balance
                .checked_add(amount)
                .expect("Recipient balance overflow");

            vec![Some(faucet_post), Some(recipient_post)]
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
