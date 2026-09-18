use associated_token_account_core::Instruction;
use lee_core::program::{
    ProgramCall, ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
};

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let (state_diffs, chained_calls) = match instruction {
        Instruction::Create { token_program_id } => {
            let [owner, token_definition, ata_account] = pre_states
                .try_into()
                .expect("Create instruction requires exactly three accounts");
            associated_token_account_program::create::create_associated_token_account(
                owner,
                token_definition,
                ata_account,
                self_account_id,
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
                self_account_id,
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
                self_account_id,
                token_program_id,
                amount,
            )
        }
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
