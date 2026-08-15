use borsh::to_vec;
use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, PdaSeed, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

/// Proxy for spending from a private PDA via `simple_transfer`.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `simple_transfer`.
/// The `AccountId` in the instruction must be the dispatch address of the transfer program.
type Instruction = (PdaSeed, u128, AccountId);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount, simple_transfer_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let first_post = AccountPostState::new(first.account.clone());
    let second_post = AccountPostState::new(second.account.clone());

    let mut first_for_callee = first.clone();
    first_for_callee.is_authorized = true;

    let chained_call = ChainedCall {
        program_account_id: simple_transfer_id,
        instruction_data: to_vec(&amount).unwrap(),
        pre_states: vec![first_for_callee, second.clone()],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![first, second],
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
