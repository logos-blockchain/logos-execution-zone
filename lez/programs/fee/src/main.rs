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
    account::{AccountWithMetadata, BalanceDiff},
    program::{
        AccountStateDiff, ProgramCall, ProgramId, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = call
    else {
        respond_unsupported_call(call);
    };
    assert!(
        caller_program_id.is_none(),
        "Fee program is only invoked as a top-level system transaction"
    );

    let state_diffs = match instruction {
        Instruction::Distribute(summary) => distribute(self_program_id, pre_states, summary),
        Instruction::Refund { amount } => refund(self_program_id, pre_states, amount),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        state_diffs,
    )
    .write();
}

/// Block-tail distribution over `[state, escrow, inbox, producer]`.
fn distribute(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    summary: BlockFeeSummary,
) -> Vec<AccountStateDiff> {
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

    let post_state_data = fee_state
        .to_bytes()
        .try_into()
        .expect("FeeState data should fit in account data");
    let state_diff = AccountStateDiff::new(pre_state, BalanceDiff::Add(0), post_state_data);

    // Money movement: inbox drains fully (base revenue to escrow, tips to the
    // producer); the smoothed payout leaves escrow for the producer. Escrow's net
    // delta is `revenue_base - payout`, which can be negative (drawing down escrow's
    // existing reserve) — the protocol rejects it if that would underflow.
    let escrow_data = pre_escrow.account.data.clone();
    let escrow_diff_balance = if summary.revenue_base >= payout {
        BalanceDiff::Add(
            summary
                .revenue_base
                .checked_sub(payout)
                .expect("revenue_base >= payout checked above"),
        )
    } else {
        BalanceDiff::Sub(
            payout
                .checked_sub(summary.revenue_base)
                .expect("payout > revenue_base checked above"),
        )
    };
    let escrow_diff = AccountStateDiff::new(pre_escrow, escrow_diff_balance, escrow_data);

    let inbox_drain = pre_inbox.account.balance;
    let inbox_data = pre_inbox.account.data.clone();
    let inbox_diff = AccountStateDiff::new(pre_inbox, BalanceDiff::Sub(inbox_drain), inbox_data);

    let producer_credit = payout
        .checked_add(summary.revenue_tip)
        .expect("producer credit fits u128");
    let producer_data = pre_producer.account.data.clone();
    let producer_diff = AccountStateDiff::new(
        pre_producer,
        BalanceDiff::Add(producer_credit),
        producer_data,
    );

    vec![state_diff, escrow_diff, inbox_diff, producer_diff]
}

/// Per-transaction refund over `[inbox, payer]`: return `amount` from the inbox
/// to the payer. The fee program owns the inbox, so debiting it is legal; the
/// payer credit is an ordinary balance increase and needs no authorization.
fn refund(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    amount: u128,
) -> Vec<AccountStateDiff> {
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

    let inbox_data = pre_inbox.account.data.clone();
    let payer_data = pre_payer.account.data.clone();

    let inbox_diff = AccountStateDiff::new(pre_inbox, BalanceDiff::Sub(amount), inbox_data);
    let payer_diff = AccountStateDiff::new(pre_payer, BalanceDiff::Add(amount), payer_data);

    vec![inbox_diff, payer_diff]
}
