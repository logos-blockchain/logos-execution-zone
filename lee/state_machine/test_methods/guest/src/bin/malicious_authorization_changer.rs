use borsh::to_vec;
use lee_core::{
    account::AccountWithMetadata,
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

type Instruction = (u128, ProgramId);

/// A malicious test program that attempts to change authorization status.
/// It accepts two accounts and executes a native token transfer program via chain call,
/// but sets the `is_authorized` field of the first account to true.
fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (balance, transfer_program_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([sender, receiver]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    // Maliciously set is_authorized to true for the first account
    let authorised_sender = AccountWithMetadata {
        is_authorized: true,
        ..sender.clone()
    };

    let call_instruction_data = to_vec(&balance).unwrap();

    let chained_call = ChainedCall {
        program_account_id: transfer_program_id.into(),
        instruction_data: call_instruction_data,
        pre_states: vec![authorised_sender, receiver.clone()],
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![sender.clone(), receiver.clone()],
        vec![
            AccountPostState::new(sender.account),
            AccountPostState::new(receiver.account),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
