//! Flash swap initiator, demonstrates the "prep → callback → assert" pattern using
//! generalized multi tail-calls with `self_program_id` and `caller_program_id`.
//!
//! # Pattern
//!
//! A flash swap lets a program optimistically transfer tokens out, run arbitrary user
//! logic (the callback), then assert that invariants hold after the callback. The entire
//! sequence is a single atomic transaction: if any step fails, all state changes roll back.
//!
//! # How it works
//!
//! This program handles two instruction variants:
//!
//! - `Initiate` (external): the top-level entrypoint. Emits 3 chained calls:
//!   1. Token transfer out (vault → receiver)
//!   2. User callback (arbitrary logic, e.g. arbitrage)
//!   3. Self-call to `InvariantCheck` (using `self_program_id` to reference itself)
//!
//! - `InvariantCheck` (internal): enforces that the vault balance was restored after the callback.
//!   Uses `caller_program_id == Some(self_program_id)` to prevent standalone calls (this is the
//!   visibility enforcement mechanism).
//!
//! # What this demonstrates
//!
//! - `self_program_id`: enables a program to chain back to itself (step 3 above)
//! - `caller_program_id`: enables a program to restrict which callers can invoke an instruction
//! - Pre-simulated intermediate states: the initiator must compute expected intermediate account
//!   states and embed them in the instruction. The node validates them deterministically.
//! - Atomic rollback: if the callback doesn't return funds, the invariant check fails, and all
//!   state changes from steps 1 and 2 are rolled back automatically.
//!
//! # Tests
//!
//! See `nssa/src/state.rs` for integration tests:
//! - `flash_swap_successful`: full round-trip, funds returned, state unchanged
//! - `flash_swap_callback_keeps_funds_rollback`: callback keeps funds, full rollback
//! - `flash_swap_self_call_targets_correct_program`: zero-amount self-call isolation test
//! - `flash_swap_standalone_invariant_check_rejected`: `caller_program_id` access control

use nssa_core::{
    account::AccountWithMetadata,
    program::{
        AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
        read_nssa_inputs,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "guest program enum, boxing adds unnecessary complexity"
)]
pub enum FlashSwapInstruction {
    /// External entrypoint: initiate a flash swap.
    ///
    /// Emits 3 chained calls:
    /// 1. Token transfer (vault → receiver, `amount_out`)
    /// 2. Callback (user logic, e.g. arbitrage)
    /// 3. Self-call `InvariantCheck` (verify vault balance did not decrease)
    ///
    /// The caller must pre-simulate the entire call graph and provide the expected
    /// intermediate account states. The node validates them deterministically at each step.
    Initiate {
        token_program_id: ProgramId,
        callback_program_id: ProgramId,
        amount_out: u128,
        callback_instruction_data: Vec<u32>,
        /// Expected vault state after the token transfer (vault balance -= `amount_out`).
        vault_after_transfer: AccountWithMetadata,
        /// Expected receiver state after the token transfer (receiver balance += `amount_out`).
        receiver_after_transfer: AccountWithMetadata,
        /// Expected vault state after the callback completes (should match initial balance
        /// if the callback correctly returns funds).
        vault_after_callback: AccountWithMetadata,
    },
    /// Internal: verify the vault invariant holds after callback execution.
    ///
    /// Access control: only callable as a chained call from this program itself.
    /// This is enforced by checking `caller_program_id == Some(self_program_id)`.
    /// Any attempt to call this instruction as a standalone top-level transaction
    /// will be rejected because `caller_program_id` will be `None`.
    InvariantCheck { min_vault_balance: u128 },
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<FlashSwapInstruction>();

    match instruction {
        FlashSwapInstruction::Initiate {
            token_program_id,
            callback_program_id,
            amount_out,
            callback_instruction_data,
            vault_after_transfer,
            receiver_after_transfer,
            vault_after_callback,
        } => {
            let Ok([vault_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
                panic!("Initiate requires exactly 2 accounts: vault, receiver");
            };

            // Capture initial vault balance, the invariant check will verify it is restored.
            let min_vault_balance = vault_pre.account.balance;

            // Chained call 1: Token transfer (vault → receiver).
            // The vault is a PDA of this initiator program (seed = [0_u8; 32]), so we provide
            // the PDA seed to authorize the token program to debit the vault on our behalf.
            // Mark the vault as authorized since it will be PDA-authorized in this chained call.
            let mut vault_authorized = vault_pre.clone();
            vault_authorized.is_authorized = true;
            let transfer_instruction =
                risc0_zkvm::serde::to_vec(&amount_out).expect("transfer instruction serialization");
            let call_1 = ChainedCall {
                program_id: token_program_id,
                pre_states: vec![vault_authorized, receiver_pre.clone()],
                instruction_data: transfer_instruction,
                pda_seeds: vec![PdaSeed::new([0_u8; 32])],
            };

            // Chained call 2: User callback.
            // Receives the post-transfer states as its pre_states. The callback may run
            // arbitrary logic (arbitrage, etc.) and is expected to return funds to the vault.
            let call_2 = ChainedCall {
                program_id: callback_program_id,
                pre_states: vec![vault_after_transfer, receiver_after_transfer],
                instruction_data: callback_instruction_data,
                pda_seeds: vec![],
            };

            // Chained call 3: Self-call to enforce the invariant.
            // Uses `self_program_id` to reference this program, the key feature that enables
            // the "prep → callback → assert" pattern without a separate checker program.
            // If the callback did not return funds, vault_after_callback.balance <
            // min_vault_balance and this call will panic, rolling back the entire
            // transaction.
            let invariant_instruction =
                risc0_zkvm::serde::to_vec(&FlashSwapInstruction::InvariantCheck {
                    min_vault_balance,
                })
                .expect("invariant instruction serialization");
            let call_3 = ChainedCall {
                program_id: self_program_id, // self-referential chained call
                pre_states: vec![vault_after_callback],
                instruction_data: invariant_instruction,
                pda_seeds: vec![],
            };

            // The initiator itself makes no direct state changes.
            // All mutations happen inside the chained calls (token transfers).
            ProgramOutput::new(
                self_program_id,
                instruction_words,
                vec![vault_pre.clone(), receiver_pre.clone()],
                vec![
                    AccountPostState::new(vault_pre.account),
                    AccountPostState::new(receiver_pre.account),
                ],
            )
            .with_chained_calls(vec![call_1, call_2, call_3])
            .write();
        }

        FlashSwapInstruction::InvariantCheck { min_vault_balance } => {
            // Visibility enforcement: `InvariantCheck` is an internal instruction.
            // It must only be called as a chained call from this program itself (via `Initiate`).
            // When called as a top-level transaction, `caller_program_id` is `None` → panics.
            // When called as a chained call from `Initiate`, `caller_program_id` is
            // `Some(self_program_id)` → passes.
            assert!(
                caller_program_id == Some(self_program_id),
                "InvariantCheck is an internal instruction: must be called by flash_swap_initiator \
                 via a chained call, got caller_program_id: {caller_program_id:?}",
            );

            let Ok([vault]) = <[_; 1]>::try_from(pre_states) else {
                panic!("InvariantCheck requires exactly 1 account: vault");
            };

            // The core invariant: vault balance must not have decreased.
            // If the callback returned funds, this passes. If not, this panics and
            // the entire transaction (including the prior token transfer) rolls back.
            assert!(
                vault.account.balance >= min_vault_balance,
                "Flash swap invariant violated: vault balance {} < minimum {}",
                vault.account.balance,
                min_vault_balance
            );

            // Pass-through: no state changes in the invariant check step.
            ProgramOutput::new(
                self_program_id,
                instruction_words,
                vec![vault.clone()],
                vec![AccountPostState::new(vault.account)],
            )
            .write();
        }
    }
}
