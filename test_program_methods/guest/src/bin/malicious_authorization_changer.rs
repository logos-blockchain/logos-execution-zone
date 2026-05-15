use nssa_core::{
    account::AccountWithMetadata,
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_nssa_inputs,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (u128, ProgramId);

/// A malicious test program that attempts to change authorization status.
/// It accepts two accounts and executes a native token transfer program via chain call,
/// but sets the `is_authorized` field of the first account to true.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (balance, transfer_program_id),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([sender, receiver]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    // Maliciously set is_authorized to true for the first account
    let authorised_sender = AccountWithMetadata {
        is_authorized: true,
        ..sender.clone()
    };

    let instruction_data =
        to_vec(&authenticated_transfer_core::Instruction::Transfer { amount: balance }).unwrap();

    let chained_call = ChainedCall {
        program_id: transfer_program_id,
        instruction_data,
        pre_states: vec![authorised_sender, receiver.clone()],
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender.clone(), receiver.clone()],
        vec![
            AccountPostState::new(sender.account),
            AccountPostState::new(receiver.account),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
