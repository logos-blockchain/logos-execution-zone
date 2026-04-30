use nssa_core::program::{
    AccountPostState, ChainedCall, Claim, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
    read_nssa_inputs,
};

/// Single program for group PDA operations. Owns and operates the PDA directly.
///
/// Instruction: `(pda_seed, noop_program_id, amount, is_deposit)`.
/// Pre-states: `[group_pda, counterparty]`.
///
/// **Deposit** (`is_deposit = true`, new PDA):
/// Claims PDA via `Claim::Pda(seed)`, increases PDA balance, decreases counterparty.
/// Counterparty must be authorized and owned by this program (or uninitialized).
///
/// **Spend** (`is_deposit = false`, existing PDA):
/// Decreases PDA balance (this program owns it), increases counterparty.
/// Chains to a noop callee with `pda_seeds` to establish the mask-3 binding
/// that the circuit requires for existing private PDAs.
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
            instruction: (pda_seed, noop_id, amount, is_deposit),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pda_pre, counterparty_pre]) = <[_; 2]>::try_from(pre_states.clone()) else {
        panic!("expected exactly 2 pre_states: [group_pda, counterparty]");
    };

    if is_deposit {
        // Deposit: claim PDA, transfer balance from counterparty to PDA.
        // Both accounts must be owned by this program (or uninitialized) for
        // validate_execution to allow balance changes.
        assert!(
            counterparty_pre.is_authorized,
            "Counterparty must be authorized to deposit"
        );

        let mut pda_account = pda_pre.account;
        let mut counterparty_account = counterparty_pre.account;

        pda_account.balance = pda_account
            .balance
            .checked_add(amount)
            .expect("PDA balance overflow");
        counterparty_account.balance = counterparty_account
            .balance
            .checked_sub(amount)
            .expect("Counterparty has insufficient balance");

        let pda_post = AccountPostState::new_claimed_if_default(pda_account, Claim::Pda(pda_seed));
        let counterparty_post = AccountPostState::new(counterparty_account);

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![pda_post, counterparty_post],
        )
        .write();
    } else {
        // Spend: decrease PDA balance (owned by this program), increase counterparty.
        // Chain to noop with pda_seeds to establish the mask-3 binding for the
        // existing PDA. The noop's pre_states must match our post_states.
        // Authorization is enforced by the circuit's binding check, not here.

        let mut pda_account = pda_pre.account.clone();
        let mut counterparty_account = counterparty_pre.account.clone();

        pda_account.balance = pda_account
            .balance
            .checked_sub(amount)
            .expect("PDA has insufficient balance");
        counterparty_account.balance = counterparty_account
            .balance
            .checked_add(amount)
            .expect("Counterparty balance overflow");

        let pda_post = AccountPostState::new(pda_account.clone());
        let counterparty_post = AccountPostState::new(counterparty_account.clone());

        // Chain to noop solely to establish the mask-3 binding via pda_seeds.
        let mut noop_pda_pre = pda_pre;
        noop_pda_pre.account = pda_account;
        noop_pda_pre.is_authorized = true;

        let mut noop_counterparty_pre = counterparty_pre;
        noop_counterparty_pre.account = counterparty_account;

        let noop_call = ChainedCall::new(noop_id, vec![noop_pda_pre, noop_counterparty_pre], &())
            .with_pda_seeds(vec![pda_seed]);

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![pda_post, counterparty_post],
        )
        .with_chained_calls(vec![noop_call])
        .write();
    }
}
