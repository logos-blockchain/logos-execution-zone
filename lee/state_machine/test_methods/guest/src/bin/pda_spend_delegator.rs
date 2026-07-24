use lee_core::program::{
    AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};
use risc0_zkvm::serde::to_vec;

// Spends an owned private PDA by delegating authorization to its owner program (the parity shape,
// identical to how a public PDA is spent): the PDA is referenced unauthorized at the top level, and
// authorization is established only in the chained call, where `pda_seeds` binds
// `(owner_program_id, seed) -> account_id` and the delegated pre_state is marked authorized.
//
// `pre_states = [pda (unauthorized at root), recipient]`.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, amount, owner_program_id),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pda, recipient]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let pda_post = AccountPostState::new(pda.account.clone());
    let recipient_post = AccountPostState::new(recipient.account.clone());

    let mut pda_delegated = pda.clone();
    pda_delegated.is_authorized = true;

    let chained_call = ChainedCall {
        program_id: owner_program_id,
        instruction_data: to_vec(&amount).unwrap(),
        pre_states: vec![pda_delegated, recipient.clone()],
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
