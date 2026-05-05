use nssa_core::program::{
    AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
    read_nssa_inputs,
};
use risc0_zkvm::serde::to_vec;

/// Spends from a private PDA by proxying the debit through auth_transfer.
///
/// pre_states[0] = the private PDA (must be authorized)
/// pre_states[1] = the recipient
///
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to auth_transfer.
/// Funding a PDA is done by calling auth_transfer directly (no proxy needed).
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, amount, auth_transfer_id),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pda, recipient]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    assert!(pda.is_authorized, "PDA must be authorized");

    let pda_post = AccountPostState::new(pda.account.clone());
    let recipient_post = AccountPostState::new(recipient.account.clone());

    let chained_call = ChainedCall {
        program_id: auth_transfer_id,
        instruction_data: to_vec(&amount).unwrap(),
        pre_states: vec![pda.clone(), recipient.clone()],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pda, recipient],
        vec![pda_post, recipient_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
