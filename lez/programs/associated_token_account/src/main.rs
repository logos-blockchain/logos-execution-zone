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
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let pre_states_clone = pre_states.clone();

    let (post_states, chained_calls) = match instruction {
        Instruction::Create { ata_program_id } => {
            let [owner, token_definition, ata_account] = pre_states
                .try_into()
                .expect("Create instruction requires exactly three accounts");
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
            let [owner, sender_ata, recipient] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly three accounts");
            associated_token_account_program::transfer::transfer_from_associated_token_account(
                owner,
                sender_ata,
                recipient,
                ata_program_id,
                amount,
            )
        }
        Instruction::TransferPrivate {
            recipient_seed,
            senders,
        } => {
            let mut accounts = pre_states;
            let recipient = accounts
                .pop()
                .expect("TransferPrivate instruction requires a recipient account");
            let mut accounts = accounts.into_iter();
            let token_definition = accounts
                .next()
                .expect("TransferPrivate instruction requires a token definition account");
            assert_eq!(
                accounts.len(),
                senders.len(),
                "TransferPrivate instruction requires exactly one account per sender"
            );
            let sender_states = accounts
                .zip(senders)
                .map(|(account, (seed, amount))| (account, seed, amount))
                .collect();
            associated_token_account_program::transfer_private::transfer_to_private_associated_token_account(
                token_definition,
                sender_states,
                recipient,
                recipient_seed,
            )
        }
        Instruction::Burn {
            ata_program_id,
            amount,
        } => {
            let [owner, holder_ata, token_definition] = pre_states
                .try_into()
                .expect("Burn instruction requires exactly three accounts");
            associated_token_account_program::burn::burn_from_associated_token_account(
                owner,
                holder_ata,
                token_definition,
                ata_program_id,
                amount,
            )
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
