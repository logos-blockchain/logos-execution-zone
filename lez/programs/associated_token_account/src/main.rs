use associated_token_account_core::Instruction;
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

    let pre_states_clone = pre_states.clone();

    let (post_states, chained_calls) = match instruction {
        Instruction::Create { token_program_id } => {
            let [owner, token_definition, ata_account] = pre_states
                .try_into()
                .expect("Create instruction requires exactly three accounts");
            associated_token_account_program::create::create_associated_token_account(
                owner,
                token_definition,
                ata_account,
                self_program_id,
                token_program_id,
            )
        }
        Instruction::Transfer {
            token_program_id,
            amount,
        } => {
            let [owner, sender_ata, recipient] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly three accounts");
            associated_token_account_program::transfer::transfer_from_associated_token_account(
                owner,
                sender_ata,
                recipient,
                self_program_id,
                token_program_id,
                amount,
            )
        }
        Instruction::Burn {
            token_program_id,
            amount,
        } => {
            let [owner, holder_ata, token_definition] = pre_states
                .try_into()
                .expect("Burn instruction requires exactly three accounts");
            associated_token_account_program::burn::burn_from_associated_token_account(
                owner,
                holder_ata,
                token_definition,
                self_program_id,
                token_program_id,
                amount,
            )
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
