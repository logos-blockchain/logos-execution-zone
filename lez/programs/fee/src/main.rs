//! Fee Program.
//!
//! A system program that owns the fee subsystem's accounts: the fee-state
//! account (base fees, payout window), the escrow account (payout smoothing),
//! and the inbox account (per-block fee collection). Invoked exclusively by the
//! sequencer as the second-to-last transaction of every block, immediately
//! before the clock invocation. Fee accounts are assigned to the fee program at
//! genesis, so no claiming is required here.
//!
//! Skeleton stage: verifies its accounts and echoes them unchanged; the block
//! fee summary is validated byte-for-byte (all-zero) by the transition.

use fee_core::Instruction;
use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: _summary,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

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
    if pre_state.account.program_owner != self_program_id
        || pre_escrow.account.program_owner != self_program_id
        || pre_inbox.account.program_owner != self_program_id
    {
        panic!("Fee accounts must be owned by the fee program");
    }

    let posts = vec![
        AccountPostState::new(pre_state.account.clone()),
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
