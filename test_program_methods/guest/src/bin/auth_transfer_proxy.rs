use nssa_core::program::{
    AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
    read_nssa_inputs,
};

/// PDA authorization program that delegates balance operations to `authenticated_transfer`.
///
/// The PDA is owned by `authenticated_transfer`, not by this program. This program's role
/// is solely to provide PDA authorization via `pda_seeds` in chained calls.
///
/// Instruction: `(pda_seed, auth_transfer_id, amount, is_withdraw)`.
///
/// **Init** (`is_withdraw = false`, 1 pre-state `[pda]`):
/// Chains to `authenticated_transfer` with `instruction=0` (init path) and `pda_seeds=[seed]`
/// to initialize the PDA under `authenticated_transfer`'s ownership.
///
/// **Withdraw** (`is_withdraw = true`, 2 pre-states `[pda, recipient]`):
/// Chains to `authenticated_transfer` with the amount and `pda_seeds=[seed]` to authorize
/// the PDA for a balance transfer. The actual balance modification happens in
/// `authenticated_transfer`, not here.
///
/// **Deposit**: done directly via `authenticated_transfer` (no need for this program).
type Instruction = (PdaSeed, ProgramId, u128, bool);

#[expect(
    clippy::allow_attributes,
    reason = "allow is needed because the clones are only redundant in test compilation"
)]
#[allow(
    clippy::redundant_clone,
    reason = "clones needed in non-test compilation"
)]
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (pda_seed, auth_transfer_id, amount, is_withdraw),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    if is_withdraw {
        let Ok([pda_pre, recipient_pre]) = <[_; 2]>::try_from(pre_states.clone()) else {
            panic!("expected exactly 2 pre_states for withdraw: [pda, recipient]");
        };

        // Post-states stay unchanged in this program. The actual balance transfer
        // happens in the chained call to authenticated_transfer.
        let pda_post = AccountPostState::new(pda_pre.account.clone());
        let recipient_post = AccountPostState::new(recipient_pre.account.clone());

        // Chain to authenticated_transfer with pda_seeds to authorize the PDA.
        // The circuit's resolve_authorization_and_record_bindings establishes the
        // private PDA (seed, npk) binding when pda_seeds match the private PDA derivation.
        let mut auth_pda_pre = pda_pre;
        auth_pda_pre.is_authorized = true;
        let auth_call =
            ChainedCall::new(auth_transfer_id, vec![auth_pda_pre, recipient_pre], &amount)
                .with_pda_seeds(vec![pda_seed]);

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![pda_post, recipient_post],
        )
        .with_chained_calls(vec![auth_call])
        .write();
    } else {
        // Init: initialize the PDA under authenticated_transfer's ownership.
        let Ok([pda_pre]) = <[_; 1]>::try_from(pre_states.clone()) else {
            panic!("expected exactly 1 pre_state for init: [pda]");
        };

        let pda_post = AccountPostState::new(pda_pre.account.clone());

        // Chain to authenticated_transfer with instruction=0 (init path) and pda_seeds
        // to authorize the PDA. authenticated_transfer will claim it with Claim::Authorized.
        let mut auth_pda_pre = pda_pre;
        auth_pda_pre.is_authorized = true;
        let auth_call = ChainedCall::new(auth_transfer_id, vec![auth_pda_pre], &0_u128)
            .with_pda_seeds(vec![pda_seed]);

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![pda_post],
        )
        .with_chained_calls(vec![auth_call])
        .write();
    }
}
