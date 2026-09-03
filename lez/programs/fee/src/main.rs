use authenticated_transfer_core::custody_transfer;
use fee_core::{
    BlockFeeSummary, Instruction, fee_escrow_seed, fee_inbox_seed, market, state::FeeState,
};
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
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

    let (pre_states, post_states, chained_calls) = match instruction {
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
    .with_chained_calls(chained_calls)
    .write();
}

/// Every balance leaves a fee PDA through a chained authenticated transfer the PDA's seed
/// authorizes; the fee program itself only rewrites its state account.
fn distribute(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    summary: BlockFeeSummary,
) -> (Vec<AccountWithMetadata>, Vec<Account>, Vec<ChainedCall>) {
    let Ok([pre_state, pre_escrow, pre_inbox, pre_producer]) = <[_; 4]>::try_from(pre_states)
    else {
        panic!("Distribute requires exactly 4 accounts");
    };
    if pre_state.account_id != fee_core::compute_fee_state_account_id(self_program_id)
        || pre_escrow.account_id != fee_core::compute_fee_escrow_account_id(self_program_id)
        || pre_inbox.account_id != fee_core::compute_fee_inbox_account_id(self_program_id)
    {
        panic!("Invalid input accounts");
    }
    if pre_state.account.program_owner != self_program_id.into()
        || pre_escrow.account.program_owner != self_program_id.into()
        || pre_inbox.account.program_owner != self_program_id.into()
    {
        panic!("Fee accounts must be owned by the fee program");
    }
    if summary.gas_used_exec > market::MAX_GAS_EXEC || summary.gas_used_stor > market::MAX_GAS_STOR
    {
        panic!("Block fee summary exceeds per-block gas caps");
    }
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

    let inbox = pre_inbox.account_id;
    let escrow = pre_escrow.account_id;
    let producer = pre_producer.account_id;
    // Order matters: the escrow receives the base before it pays out of it.
    let chained_calls = [
        (inbox, fee_inbox_seed(), escrow, summary.revenue_base),
        (inbox, fee_inbox_seed(), producer, summary.revenue_tip),
        (escrow, fee_escrow_seed(), producer, payout),
    ]
    .into_iter()
    .filter(|(_, _, _, amount)| *amount > 0)
    .map(|(from, seed, to, amount)| custody_transfer(from, seed, to, amount))
    .collect();

    let post_states = vec![
        post_state_account,
        pre_escrow.account.clone(),
        pre_inbox.account.clone(),
        pre_producer.account.clone(),
    ];
    (
        vec![pre_state, pre_escrow, pre_inbox, pre_producer],
        post_states,
        chained_calls,
    )
}

fn refund(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    amount: u128,
) -> (Vec<AccountWithMetadata>, Vec<Account>, Vec<ChainedCall>) {
    let Ok([pre_inbox, pre_payer]) = <[_; 2]>::try_from(pre_states) else {
        panic!("Refund requires exactly 2 accounts");
    };
    assert!(
        pre_inbox.account_id == fee_core::compute_fee_inbox_account_id(self_program_id),
        "Invalid inbox account"
    );
    assert!(
        pre_inbox.account.program_owner == self_program_id.into(),
        "Inbox must be owned by the fee program"
    );
    let chained_calls = vec![custody_transfer(
        pre_inbox.account_id,
        fee_inbox_seed(),
        pre_payer.account_id,
        amount,
    )];
    let post_states = vec![pre_inbox.account.clone(), pre_payer.account.clone()];
    (vec![pre_inbox, pre_payer], post_states, chained_calls)
}
