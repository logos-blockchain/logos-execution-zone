use associated_token_account_core::Instruction;
use lee_core::program::{ProgramCall, read_lee_call};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<Instruction>();

    let (post_states, chained_calls) = match instruction {
        Instruction::Create { ata_program_id } => {
            let [owner, token_definition, ata_account] = input.pre_states.as_slice() else {
                panic!("Create instruction requires exactly three accounts");
            };
            associated_token_account_program::create::create_associated_token_account(
                owner,
                token_definition,
                ata_account,
                ata_program_id,
            )
        }
        Instruction::Transfer {
            ata_program_id,
            amount,
        } => {
            let [owner, sender_ata, recipient] = input.pre_states.as_slice() else {
                panic!("Transfer instruction requires exactly three accounts");
            };
            associated_token_account_program::transfer::transfer_from_associated_token_account(
                owner,
                sender_ata,
                recipient,
                ata_program_id,
                amount,
            )
        }
        Instruction::Burn {
            ata_program_id,
            amount,
        } => {
            let [owner, holder_ata, token_definition] = input.pre_states.as_slice() else {
                panic!("Burn instruction requires exactly three accounts");
            };
            associated_token_account_program::burn::burn_from_associated_token_account(
                owner,
                holder_ata,
                token_definition,
                ata_program_id,
                amount,
            )
        }
    };

    input
        .into_output(post_states)
        .with_chained_calls(chained_calls)
        .write();
}
