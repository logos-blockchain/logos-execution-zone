//! Fee Program.
//!
//! A system program that owns the fee subsystem's accounts: the fee-state
//! account (base fees, payout window), the escrow account (payout smoothing),
//! and the inbox account (per-block fee collection). Invoked exclusively by the
//! sequencer as the second-to-last transaction of every block, immediately
//! before the clock invocation. Fee accounts are assigned to the fee program at
//! genesis, so no claiming is required here.
//!
//! Applies the per-block market update to the fee-state account; the block fee
//! summary is validated byte-for-byte (all-zero until metering lands), so
//! escrow and inbox stay untouched.

use fee_core::{Instruction, market, state::FeeState};
use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: summary,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();
    assert!(
        caller_program_id.is_none(),
        "Fee program is only invoked as a top-level sequencer transaction"
    );

    let Ok([pre_state, pre_escrow, pre_inbox]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Invalid number of input accounts");
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

    let mut fee_state = FeeState::from_bytes(&pre_state.account.data.clone().into_inner());
    let payout = fee_state.apply_block(&summary);
    // Until charging lands the summary is all-zero, so no payout can be owed.
    assert!(payout == 0, "no payout can accrue under zero fees");

    let mut post_state_account = pre_state.account.clone();
    post_state_account.data = fee_state
        .to_bytes()
        .try_into()
        .expect("FeeState data should fit in account data");

    let posts = vec![
        AccountPostState::new(post_state_account),
        AccountPostState::new(pre_escrow.account.clone()),
        AccountPostState::new(pre_inbox.account.clone()),
    ];

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre_state, pre_escrow, pre_inbox],
        posts,
    )
    .write();
}
