use std::collections::HashMap;

use lee_core::account::{Account, AccountId, Nonce};

use crate::{
    PrivateKey, PublicKey, V03State,
    error::LeeError,
    public_transaction::{Message, WitnessSet},
    validated_state_diff::ValidatedStateDiff,
};

fn public_state_from_balances(initial_data: &[(AccountId, u128)]) -> HashMap<AccountId, Account> {
    initial_data
        .iter()
        .copied()
        .map(|(account_id, balance)| {
            (
                account_id,
                Account {
                    program_owner: crate::test_methods::simple_balance_transfer().id().into(),
                    balance,
                    ..Account::default()
                },
            )
        })
        .collect()
}

#[test]
fn public_diff_reflects_a_successful_transfer() {
    // A successful native transfer must record the debited sender in
    // `public_diff()`.  Catches the mutation that replaces `public_diff` with
    // `HashMap::new()` (which would hide every account change).
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id = crate::test_methods::simple_balance_transfer().id();
    let message =
        Message::try_new(program_id, vec![from, to], vec![Nonce(0), Nonce(0)], 5_u128).unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("a valid native transfer must validate");
    let public_diff = diff.public_diff();

    assert!(
        public_diff.contains_key(&from),
        "public_diff must contain the debited sender",
    );
    assert_eq!(
        public_diff[&from].balance, 95,
        "sender balance in the diff must reflect the debit",
    );
}

/// Regression test: a `PrivacyPreservingTransaction` carrying a structurally invalid
/// proof must be rejected with a clean `Err`.
#[test]
fn privacy_garbage_proof_is_rejected() {
    use lee_core::{
        Commitment, EncryptedAccountData, Nullifier, PrivateAction,
        account::Account,
        encryption::{Ciphertext, EphemeralPublicKey},
        program::{BlockValidityWindow, TimestampValidityWindow},
    };

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::Proof, message::Message, witness_set::WitnessSet,
        },
    };

    let state = V03State::new();

    // Minimal message that passes every check up to proof verification: a single
    // commitment satisfies the non-empty requirement, no signers makes the
    // nonce/signature checks vacuously true, and unbounded validity windows are valid
    // for any block/timestamp.
    let account_id = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([1_u8; 32]).unwrap(),
    ));
    let commitment = Commitment::new(&account_id, &Account::default());
    let message = Message {
        public_actions: vec![],
        nonces: vec![],
        private_actions: vec![PrivateAction {
            nullifier: Nullifier::for_account_initialization(&account_id),
            root: [0; 32],
            commitment,
            encrypted_post_state: EncryptedAccountData {
                ciphertext: Ciphertext::from_inner(vec![]),
                epk: EphemeralPublicKey(vec![]),
                view_tag: 0,
            },
        }],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    };

    // Garbage proof bytes: not a valid borsh-encoded `InnerReceipt`.
    let garbage_proof = Proof::from_inner(vec![0xff_u8; 64]);
    let witness_set = WitnessSet::for_message(&message, garbage_proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

    match result {
        Err(LeeError::InvalidPrivacyPreservingProof) => {}
        Err(other) => panic!("expected InvalidPrivacyPreservingProof, got {other:?}"),
        Ok(_) => panic!("garbage proof was accepted instead of rejected"),
    }
}

fn metering_transfer_fixture() -> (V03State, crate::PublicTransaction) {
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id = crate::test_methods::simple_balance_transfer().id();
    let message =
        Message::try_new(program_id, vec![from, to], vec![Nonce(0), Nonce(0)], 5_u128).unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    (state, crate::PublicTransaction::new(message, witness_set))
}

#[test]
fn budgeted_execution_reports_cycles_and_matching_diff() {
    // The same tx through both entry points: identical diff, nonzero cycles.
    let (state, tx) = metering_transfer_fixture();
    let (diff, outcome) = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect("executes");
    let unbudgeted =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).expect("executes");
    assert_eq!(diff.public_diff(), unbudgeted.public_diff());
    assert!(outcome.cycles > 0);
    assert!(outcome.cycles <= crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET);
}

#[test]
fn exhausted_budget_surfaces_out_of_gas() {
    let (state, tx) = metering_transfer_fixture();
    let result =
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, &state, 1, 0, 1_024);
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

#[test]
fn chained_calls_share_one_budget() {
    // A chain-calling tx must exhaust when the budget covers less than the
    // whole chain, even though each individual call would fit.
    let chain_caller = crate::test_methods::chain_caller();
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 1_000), (to, 0)]))
        .with_test_programs();
    let instruction: (
        u128,
        lee_core::program::ProgramId,
        u32,
        Option<lee_core::program::PdaSeed>,
    ) = (
        37,
        crate::test_methods::simple_balance_transfer().id(),
        2,
        None,
    );
    // The chain_caller program permutes the account order in the chain call.
    let message = Message::try_new(
        chain_caller.id(),
        vec![to, from],
        vec![Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let full_cycles = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect("executes under the default budget")
    .1
    .cycles;

    // `cycles()` and the session limit gate the same unpadded user-cycle
    // counter, but the limit is only checked before each instruction and one
    // instruction (an ecall) can add up to MAX_INSN_CYCLES (~25k) at once, so a
    // boundary budget (`full_cycles - 1`) can still complete. A quarter of the
    // chain's total is decisively insufficient.
    let starved_budget = full_cycles >> 2;
    let starved = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &tx,
        &state,
        1,
        0,
        starved_budget,
    );
    assert!(matches!(starved, Err(LeeError::OutOfGas { .. })));
}

#[test]
fn free_outcome_is_zero_cycles() {
    assert_eq!(crate::ExecutionOutcome::FREE.cycles, 0);
}

#[test]
fn metered_guest_panic_is_charged_the_full_budget() {
    // A transfer beyond the sender's balance panics the guest mid-execution —
    // a chargeable failure that is not OutOfGas. It still pays the whole
    // declared budget: metering written back on an error path must never
    // undercharge.
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id = crate::test_methods::simple_balance_transfer().id();
    let message = Message::try_new(
        program_id,
        vec![from, to],
        vec![Nonce(0), Nonce(0)],
        1_000_u128,
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget);
    assert_eq!(
        outcome.cycles, budget,
        "a failed execution pays its full declared budget"
    );
    result.expect("a charged revert still yields an applicable diff");
}

#[test]
fn metered_revert_reports_cycles_and_yields_a_nonce_only_diff() {
    let (mut state, tx) = metering_transfer_fixture();
    let from = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([1_u8; 32]).unwrap(),
    ));
    let to = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([2_u8; 32]).unwrap(),
    ));
    let from_before = state.get_account_by_id(from).balance;

    // A budget too small to finish the transfer: the action runs out of gas.
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, 1_024);
    assert_eq!(
        outcome.cycles, 1_024,
        "out-of-gas is metered at the whole budget"
    );

    // The revert is buried as a successful return: the diff carries no effects,
    // only the signers' nonce advances, so the charged tx cannot be replayed.
    let diff = result.expect("a reverted action still yields an applicable diff");
    assert!(
        diff.public_diff().is_empty(),
        "a reverted action moves no balances"
    );
    drop(state.apply_state_diff(diff));
    assert_eq!(
        state.get_account_by_id(from).balance,
        from_before,
        "the transfer was reverted"
    );
    assert_eq!(state.get_account_by_id(from).nonce.0, 1);
    assert_eq!(state.get_account_by_id(to).nonce.0, 1);
}
