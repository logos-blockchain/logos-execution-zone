use ata_core::Instruction;
use nssa_core::program::{ProgramInput, read_nssa_inputs, write_nssa_outputs_with_chained_call};

fn main() {
    let (
        ProgramInput {
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

    write_nssa_outputs_with_chained_call(
        instruction_words,
        pre_states_clone,
        post_states,
        chained_calls,
    );
}
