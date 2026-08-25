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
        Instruction::GenesisTransferDirect {
            recipient_program,
            amount,
        } => {
            let [faucet, recipient] = <[_; 2]>::try_from(pre_states.clone())
                .expect("TransferDirect requires exactly 2 accounts");

            assert_eq!(
                faucet.account_id,
                faucet_core::compute_faucet_account_id(self_program_id),
                "First account must be faucet PDA"
            );

            let mut faucet_post = faucet.account;
            let faucet_slot = faucet_post.slot_mut(self_program_id);
            faucet_slot.balance = faucet_slot
                .balance
                .checked_sub(amount)
                .expect("Faucet has insufficient balance");
            faucet_post.prune();

            let mut recipient_post = recipient.account;
            let recipient_slot = recipient_post.slot_mut(recipient_program);
            recipient_slot.balance = recipient_slot
                .balance
                .checked_add(amount)
                .expect("Recipient balance overflow");
            recipient_post.prune();

            vec![faucet_post, recipient_post]
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
