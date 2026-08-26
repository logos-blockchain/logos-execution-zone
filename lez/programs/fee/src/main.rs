//! Fee Program.
//!
//! A system program that owns the fee subsystem's accounts: the fee-state
//! account (base fees, payout window), the escrow account (payout smoothing),
//! and the inbox account (per-block fee collection). Fee accounts are assigned
//! to the fee program at genesis, so no claiming is required here.
//!
//! Two system-authorized instructions, neither carrying a user signature:
//! - [`Instruction::Distribute`] — the block-tail settlement invoked as the second-to-last
//!   transaction of every block: applies the per-block market update and drains the inbox (base
//!   revenue to escrow, tips to the producer), paying the smoothed payout from escrow to the
//!   producer (the fourth account).
//! - [`Instruction::Refund`] — a per-transaction refund of the unspent reserve, returning balance
//!   from the inbox to the payer. Only the fee program owns the inbox, so only it can debit it.

use fee_core::{BlockFeeSummary, Instruction, market, state::FeeState};
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();
    assert!(
        caller_program_id.is_none(),
        "Fee program is only invoked as a top-level system transaction"
    );

    let (pre_states, post_states) = match instruction {
        Instruction::Distribute(summary) => distribute(self_program_id, pre_states, summary),
        Instruction::Refund { amount } => refund(self_program_id, pre_states, amount),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}

/// Block-tail distribution over `[state, escrow, inbox, producer]`.
fn distribute(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    summary: BlockFeeSummary,
) -> (Vec<AccountWithMetadata>, Vec<AccountPostState>) {
    let Ok([pre_state, pre_escrow, pre_inbox, pre_producer]) = <[_; 4]>::try_from(pre_states)
    else {
        panic!("Distribute requires exactly 4 accounts");
    };

    // Verify pre-states correspond to the expected fee account IDs.
    if pre_state.account_id != fee_core::compute_fee_state_account_id(self_program_id)
        || pre_escrow.account_id != fee_core::compute_fee_escrow_account_id(self_program_id)
        || pre_inbox.account_id != fee_core::compute_fee_inbox_account_id(self_program_id)
    {
        panic!("Invalid input accounts");
    }

    // Verify all fee accounts are owned by this program (assigned at genesis).
    if pre_state.account.program_owner != self_program_id.into()
        || pre_escrow.account.program_owner != self_program_id.into()
        || pre_inbox.account.program_owner != self_program_id.into()
    {
        panic!("Fee accounts must be owned by the fee program");
    }

    // A summary above the per-block caps is not a valid block; the transition
    // also pins the summary byte-for-byte.
    //
    // TODO(#754): the revenue fields are not bounded here. While the summary is
    // pinned all-zero this cannot bite, but once charging lifts the pin an
    // attacker-supplied `revenue_base` near u128::MAX would reach the smoothing
    // window and trip its checked-add (a consensus fault). Bound it to
    // `gas_used_exec·base_fee_exec + gas_used_stor·base_fee_stor` then.
    if summary.gas_used_exec > market::MAX_GAS_EXEC || summary.gas_used_stor > market::MAX_GAS_STOR
    {
        panic!("Block fee summary exceeds per-block gas caps");
    }

    // Conservation pin: the transition credited exactly the block's revenue to
    // the inbox; anything else is an invalid block.
    let revenue_total = summary
        .revenue_base
        .checked_add(summary.revenue_tip)
        .expect("block revenue fits u128");
    assert!(
        pre_inbox.account.balance == revenue_total,
        "inbox balance must equal the block's revenue"
    );

    let mut fee_state = FeeState::from_bytes(&pre_state.account.data);
    let payout = fee_state.apply_block(&summary);

    let mut post_state_account = pre_state.account.clone();
    post_state_account.data = fee_state
        .to_bytes()
        .try_into()
        .expect("FeeState data should fit in account data");

    // Money movement: inbox drains fully (base revenue to escrow, tips to the
    // producer); the smoothed payout leaves escrow for the producer.
    let mut post_escrow = pre_escrow.account.clone();
    post_escrow.balance = post_escrow
        .balance
        .checked_add(summary.revenue_base)
        .expect("escrow credit fits u128")
        .checked_sub(payout)
        .expect("payout never exceeds escrow");

    let mut post_inbox = pre_inbox.account.clone();
    post_inbox.balance = 0;

    let mut post_producer = pre_producer.account.clone();
    post_producer.balance = post_producer
        .balance
        .checked_add(payout)
        .and_then(|balance| balance.checked_add(summary.revenue_tip))
        .expect("producer credit fits u128");

    let post_states = vec![
        AccountPostState::new(post_state_account),
        AccountPostState::new(post_escrow),
        AccountPostState::new(post_inbox),
        AccountPostState::new(post_producer),
    ];
    (
        vec![pre_state, pre_escrow, pre_inbox, pre_producer],
        post_states,
    )
}

/// Per-transaction refund over `[inbox, payer]`: return `amount` from the inbox
/// to the payer. The fee program owns the inbox, so debiting it is legal; the
/// payer credit is an ordinary balance increase and needs no authorization.
fn refund(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    amount: u128,
) -> (Vec<AccountWithMetadata>, Vec<AccountPostState>) {
    let Ok([pre_inbox, pre_payer]) = <[_; 2]>::try_from(pre_states) else {
        panic!("Refund requires exactly 2 accounts");
    };

    // The inbox must be this program's inbox account (and thus owned by it).
    assert!(
        pre_inbox.account_id == fee_core::compute_fee_inbox_account_id(self_program_id),
        "Invalid inbox account"
    );
    assert!(
        pre_inbox.account.program_owner == self_program_id.into(),
        "Inbox must be owned by the fee program"
    );

    let mut post_inbox = pre_inbox.account.clone();
    post_inbox.balance = post_inbox
        .balance
        .checked_sub(amount)
        .expect("refund never exceeds the inbox balance");

    let mut post_payer = pre_payer.account.clone();
    post_payer.balance = post_payer
        .balance
        .checked_add(amount)
        .expect("payer credit fits u128");

    (
        vec![pre_inbox, pre_payer],
        vec![
            AccountPostState::new(post_inbox),
            AccountPostState::new(post_payer),
        ],
    )
}
