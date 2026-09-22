//! Flash swap initiator, demonstrates the "prep → callback → assert" pattern using
//! generalized multi tail-calls with `self_account_id` and `caller_account_id`.
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
//!   3. Self-call to `InvariantCheck` (using `self_account_id` to reference itself)
//!
//! - `InvariantCheck` (internal): enforces that the vault balance was restored after the callback.
//!   Uses `caller_account_id == Some(self_account_id)` to prevent standalone calls (this is the
//!   visibility enforcement mechanism).
//!
//! # What this demonstrates
//!
//! - `self_account_id`: enables a program to chain back to itself (step 3 above)
//! - `caller_account_id`: enables a program to restrict which callers can invoke an instruction
//! - `Plan::require`: the vault balance the invariant is measured against is *supplied* in the
//!   instruction and untrusted. Promoting it to `Checked` emits the guard that pins it to the
//!   vault's actual balance, so the value cannot reach the child call unpinned.
//! - Atomic rollback: if the callback doesn't return funds, the invariant check fails, and all
//!   state changes from steps 1 and 2 are rolled back automatically.
//!
//! # Tests
//!
//! See `lee/src/state.rs` for integration tests:
//! - `flash_swap_successful`: full round-trip, funds returned, state unchanged
//! - `flash_swap_callback_keeps_funds_rollback`: callback keeps funds, full rollback
//! - `flash_swap_self_call_targets_correct_program`: zero-amount self-call isolation test
//! - `flash_swap_standalone_invariant_check_rejected`: `caller_account_id` access control

use lee_core::{
    account::ProgramShardSelector,
    native_token::{custody_transfer, decode_balance},
    program::{ChainedCall, LeeCall, PdaSeed, Plan, Proposed, read_lee_call, resolve_keep},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum FlashSwapInstruction {
    /// External entrypoint: initiate a flash swap.
    ///
    /// Emits 3 chained calls:
    /// 1. Token transfer (vault → receiver, `amount_out`)
    /// 2. Callback (user logic, e.g. arbitrage)
    /// 3. Self-call `InvariantCheck` (verify vault balance did not decrease)
    ///
    /// `vault_balance` is the caller's proposal for what the vault currently holds. It is
    /// untrusted: a guard effect pins it to the vault's real balance before it is allowed to
    /// become the invariant's floor.
    Initiate {
        callback_program_id: lee_core::account::AccountId,
        amount_out: u128,
        vault_balance: u128,
        callback_instruction_data: Vec<u8>,
    },
    /// Internal: verify the vault invariant holds after callback execution.
    ///
    /// Access control: only callable as a chained call from this program itself.
    /// This is enforced by checking `caller_account_id == Some(self_account_id)`.
    /// Any attempt to call this instruction as a standalone top-level transaction
    /// will be rejected because `caller_account_id` will be `None`.
    InvariantCheck { min_vault_balance: u128 },
}

/// It never writes: the native balance belongs to the native token program, so the only sound
/// outcome of a foreign inspection is `Keep`.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Guard {
    BalanceIs(u128),
    BalanceAtLeast(u128),
}

fn main() {
    match read_lee_call::<FlashSwapInstruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data),
        LeeCall::Resolve(input) => {
            let guard: Guard =
                borsh::from_slice(&input.effect_data).expect("the initiator wrote its own guard");
            let balance = decode_balance(&input.pre_data)
                .expect("the guarded shard is a native balance shard");
            match guard {
                Guard::BalanceIs(proposed) => assert_eq!(
                    balance, proposed,
                    "Proposed vault balance {proposed} is not the vault's actual balance \
                     {balance}"
                ),
                Guard::BalanceAtLeast(minimum) => assert!(
                    balance >= minimum,
                    "Flash swap invariant violated: vault balance {balance} < minimum {minimum}"
                ),
            }
            resolve_keep(input)
        }
    }
}

fn execute(
    input: &lee_core::program::ProgramInput<FlashSwapInstruction>,
    instruction_data: Vec<u8>,
) -> ! {
    match &input.instruction {
        FlashSwapInstruction::Initiate {
            callback_program_id,
            amount_out,
            vault_balance,
            callback_instruction_data,
        } => {
            let Ok([vault, receiver]) = <[_; 2]>::try_from(input.accounts.clone()) else {
                panic!("Initiate requires exactly 2 accounts: vault, receiver");
            };
            let mut plan = Plan::new(input, instruction_data);

            // The invariant's floor comes in with the instruction, so it is a proposal. `require`
            // emits the balance guard before returning the value, so the obligation cannot be
            // skipped; that the guard actually validates this value is the caller's pairing to
            // get right, not something `Checked` establishes.
            let min_vault_balance = plan.require(
                &vault,
                &Guard::BalanceIs(*vault_balance),
                Proposed::new(*vault_balance),
            );

            // Chained call 1: Token transfer (vault → receiver).
            // The vault is a PDA of this initiator program (seed = [0_u8; 32]), so we provide
            // the PDA seed to authorize the token program to debit the vault on our behalf.
            plan.call(custody_transfer(
                vault.account_id,
                PdaSeed::new([0; 32]),
                receiver.account_id,
                *amount_out,
            ));

            // Chained call 2: User callback. The callback may run arbitrary logic (arbitrage,
            // etc.) and is expected to return funds to the vault.
            plan.call(ChainedCall {
                program_account_id: *callback_program_id,
                shard_selectors: vec![
                    ProgramShardSelector::from(&vault),
                    ProgramShardSelector::from(&receiver),
                ],
                instruction_data: callback_instruction_data.clone(),
                pda_seeds: vec![],
            });

            // Chained call 3: Self-call to enforce the invariant.
            // Uses `self_account_id` to reference this program, the key feature that enables
            // the "prep → callback → assert" pattern without a separate checker program.
            // If the callback did not return funds, the vault's balance by this point will be
            // below `min_vault_balance` and that call's guard will panic, rolling back the
            // entire transaction.
            plan.call(ChainedCall::new(
                input.self_account_id, // self-referential chained call
                vec![ProgramShardSelector::from(&vault)],
                &FlashSwapInstruction::InvariantCheck {
                    min_vault_balance: min_vault_balance.get(),
                },
            ));

            plan.write()
        }

        FlashSwapInstruction::InvariantCheck { min_vault_balance } => {
            // Visibility enforcement: `InvariantCheck` is an internal instruction.
            // It must only be called as a chained call from this program itself (via `Initiate`).
            // When called as a top-level transaction, `caller_account_id` is `None` → panics.
            // When called as a chained call from `Initiate`, `caller_account_id` is
            // `Some(self_account_id)` → passes.
            assert_eq!(
                input.caller_account_id,
                Some(input.self_account_id),
                "InvariantCheck is an internal instruction: must be called by flash_swap_initiator \
                 via a chained call",
            );

            let Ok([vault]) = <[_; 1]>::try_from(input.accounts.clone()) else {
                panic!("InvariantCheck requires exactly 1 account: vault");
            };

            // The core invariant: vault balance must not have decreased. Checked by this
            // program's own resolver against the vault's actual balance shard.
            let mut plan = Plan::new(input, instruction_data);
            plan.effect(&vault, &Guard::BalanceAtLeast(*min_vault_balance));
            plan.write()
        }
    }
}
