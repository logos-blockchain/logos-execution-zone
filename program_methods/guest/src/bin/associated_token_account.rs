use ata_core::Instruction;
use nssa_core::program::{ProgramInput, ProgramOutput, read_nssa_inputs};

fn main() {
    let (
        ProgramInput { self_program_id: _,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let pre_states_clone = pre_states.clone();

    let (post_states, chained_calls) = match instruction {
        Instruction::Create { ata_program_id } => {
            let [owner, token_definition, ata_account] = pre_states
                .try_into()
                .expect("Create instruction requires exactly three accounts");
            ata_program::create::create_associated_token_account(
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
            let [owner, sender_ata, recipient] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly three accounts");
            ata_program::transfer::transfer_from_associated_token_account(
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
            let [owner, holder_ata, token_definition] = pre_states
                .try_into()
                .expect("Burn instruction requires exactly three accounts");
            ata_program::burn::burn_from_associated_token_account(
                owner,
                holder_ata,
                token_definition,
                ata_program_id,
                amount,
            )
        }
    };

    ProgramOutput::new(instruction_words, pre_states_clone, post_states)
        .with_chained_calls(chained_calls)
        .write();
}
