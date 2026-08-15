use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, PdaSeed, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};
use risc0_zkvm::serde::to_vec;

/// Proxy for spending from a private PDA via `auth_transfer`.
///
/// `pre_states = [pda (authorized), recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `auth_transfer`.
/// The `AccountId` in the instruction must be the dispatch address of `auth_transfer`.
type Instruction = (PdaSeed, u128, AccountId);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount, auth_transfer_id),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    assert!(first.is_authorized, "first pre_state must be authorized");

    let first_post = AccountPostState::new(first.account.clone());
    let second_post = AccountPostState::new(second.account.clone());

    let chained_call = ChainedCall {
        program_account_id: auth_transfer_id,
        instruction_data: to_vec(&authenticated_transfer_core::Instruction::Transfer { amount })
            .unwrap(),
        pre_states: vec![first.clone(), second.clone()],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![first, second],
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
