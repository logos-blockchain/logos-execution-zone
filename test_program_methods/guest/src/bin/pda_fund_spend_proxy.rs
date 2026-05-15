use nssa_core::{
    account::AccountWithMetadata,
    program::{
        AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
        read_nssa_inputs,
    },
};
use risc0_zkvm::serde::to_vec;

/// Proxy for interacting with private PDAs via `auth_transfer`.
///
/// The `is_fund` flag selects the operating mode:
///
/// - `false` (Spend): `pre_states = [pda (authorized), recipient]`. Debits the PDA. The PDA-to-npk
///   binding is established via `pda_seeds` in the chained call to `auth_transfer`.
///
/// - `true` (Fund): `pre_states = [sender (authorized), pda (foreign/uninitialized)]`. Credits the
///   PDA. A direct call to `auth_transfer` cannot bind the PDA because `auth_transfer` uses
///   `Claim::Authorized`, not `Claim::Pda`. Routing through this proxy establishes the binding via
///   `pda_seeds` in the chained call.
type Instruction = (PdaSeed, u128, ProgramId, bool);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, amount, auth_transfer_id, is_fund),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    assert!(first.is_authorized, "first pre_state must be authorized");

    let chained_pre_states = if is_fund {
        let pda_authorized = AccountWithMetadata {
            account: second.account.clone(),
            account_id: second.account_id,
            is_authorized: true,
        };
        vec![first.clone(), pda_authorized]
    } else {
        vec![first.clone(), second.clone()]
    };

    let first_post = AccountPostState::new(first.account.clone());
    let second_post = AccountPostState::new(second.account.clone());

    let chained_call = ChainedCall {
        program_id: auth_transfer_id,
        instruction_data: to_vec(&authenticated_transfer_core::Instruction::Transfer { amount })
            .unwrap(),
        pre_states: chained_pre_states,
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![first, second],
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
