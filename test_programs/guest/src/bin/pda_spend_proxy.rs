use borsh::to_vec;
use lee_core::program::{
    ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

/// Proxy for spending from a private PDA via `auth_transfer`.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The caller's `pda_seeds` authorize the PDA for `auth_transfer`; the witness binds its npk.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, amount, auth_transfer_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let first_post = first.account.clone();
    let second_post = second.account.clone();

    let mut first_for_callee = first.clone();
    first_for_callee.is_authorized = true;

    let chained_call = ChainedCall {
        program_id: auth_transfer_id,
        instruction_data: to_vec(&authenticated_transfer_core::Instruction::Transfer {
            amount,
            recipient_program: None,
        })
        .unwrap(),
        pre_states: vec![first_for_callee, second.clone()],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![first, second],
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
