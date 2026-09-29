use lee_core::account::{AccountId, Actor, Nonce};
use test_guest_core::Script;

use crate::{
    PrivateKey, PublicKey, V03State,
    error::LeeError,
    state::tests::{public_tx, scripted_id, transfer},
    validated_state_diff::ValidatedStateDiff,
};

#[test]
fn public_diff_reflects_a_successful_transfer() {
    // A successful native transfer must record the debited sender in
    // `public_diff()`.  Catches the mutation that replaces `public_diff` with
    // `HashMap::new()` (which would hide every account change).
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new().with_public_account_balances([(from, 100)]);
    let tx = public_tx(
        Actor::native_balance(from),
        vec![Actor::native_balance(from), Actor::native_balance(to)],
        vec![Nonce(0), Nonce(0)],
        transfer(to, 5),
        &[&from_key, &to_key],
    );

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("a valid native transfer must validate");
    let public_diff = diff.public_diff();

    assert!(
        public_diff.contains_key(&from),
        "public_diff must contain the debited sender",
    );
    assert_eq!(
        public_diff[&from].data.native_balance(),
        Ok(95),
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
        execution_state::{Boundary, Declared},
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
        declared: Declared::default(),
        boundary: Boundary::default(),
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
        program_image_claims: vec![],
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

fn signer() -> (PrivateKey, AccountId) {
    let key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    (key, account_id)
}

fn metering_write_fixture() -> (V03State, crate::PublicTransaction) {
    let (from_key, from) = signer();
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();

    let state = V03State::new()
        .with_public_account_balances([(from, 100)])
        .with_programs([crate::test_methods::scripted()]);
    let writer = Actor::new(from, scripted_id());
    let tx = public_tx(
        writer,
        vec![writer],
        vec![Nonce(0), Nonce(0)],
        Script::write(vec![7_u8; 4]),
        &[&from_key, &to_key],
    );
    (state, tx)
}

#[test]
fn budgeted_execution_reports_cycles_and_matching_diff() {
    // The same tx through both entry points: identical diff, nonzero cycles.
    let (state, tx) = metering_write_fixture();
    let (diff, charge) = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
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
    assert!(charge.cycles > 0);
    assert!(charge.cycles <= crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET);
}

#[test]
fn exhausted_budget_surfaces_out_of_gas() {
    let (state, tx) = metering_write_fixture();
    let result =
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, &state, 1, 0, 1_024);
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

#[test]
fn free_charge_is_zero_cycles() {
    assert_eq!(crate::ExecutionCharge::FREE.cycles, 0);
}

#[test]
fn metered_guest_panic_is_charged_the_full_budget() {
    // An unauthorized receiver panics the guest mid-execution — a chargeable
    // failure that is not OutOfGas. It still pays the whole declared budget:
    // metering written back on an error path must never undercharge.
    let (from_key, from) = signer();
    let unsigned = Actor::new(AccountId::new([2_u8; 32]), scripted_id());
    let state = V03State::new()
        .with_public_account_balances([(from, 100)])
        .with_programs([crate::test_methods::scripted()]);
    let tx = public_tx(
        unsigned,
        vec![unsigned],
        vec![Nonce(0)],
        Script::default().authorized(),
        &[&from_key],
    );

    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let (charge, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget);
    assert_eq!(
        charge.cycles, budget,
        "a panic pays its full declared budget"
    );
    result.expect("a charged revert still yields an applicable diff");
}

#[test]
fn metered_nonzero_exit_is_charged_its_metered_cycles() {
    // Unlike a panic, `env::exit(n)` keeps the session, so the revert pays what
    // it actually ran rather than the whole budget.
    let (from_key, from) = signer();
    let program_id = AccountId::from_builtin_program(crate::test_methods::exits_nonzero().id());
    let state = V03State::new()
        .with_public_account_balances([(from, 100)])
        .with_named_programs(std::iter::once((
            program_id,
            crate::test_methods::exits_nonzero(),
        )));
    let exiting = Actor::new(from, program_id);
    let tx = public_tx(exiting, vec![exiting], vec![Nonce(0)], (), &[&from_key]);

    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let (charge, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget);
    assert!(
        charge.cycles > 0 && charge.cycles < budget,
        "a non-zero exit is metered, not charged the full budget: {}",
        charge.cycles
    );
    let diff = result.expect("a charged revert still yields an applicable diff");
    assert!(
        diff.public_diff().is_empty(),
        "a reverted action moves no balances"
    );
}

#[test]
fn metered_revert_reports_cycles_and_yields_a_nonce_only_diff() {
    let (mut state, tx) = metering_write_fixture();
    let (_, from) = signer();
    let to = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([2_u8; 32]).unwrap(),
    ));
    let from_before = state.get_account_by_id(from);

    // A budget too small to finish the write: the action runs out of gas.
    let (charge, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, 1_024);
    assert_eq!(
        charge.cycles, 1_024,
        "out-of-gas is metered at the whole budget"
    );

    // The revert is buried as a successful return: the diff carries no effects,
    // only the signers' nonce advances, so the charged tx cannot be replayed.
    let diff = result.expect("a reverted action still yields an applicable diff");
    assert!(
        diff.public_diff().is_empty(),
        "a reverted action writes no shard"
    );
    drop(state.apply_state_diff(diff));
    assert_eq!(
        state.get_account_by_id(from).data,
        from_before.data,
        "the write was reverted"
    );
    assert_eq!(state.get_account_by_id(from).nonce.0, 1);
    assert_eq!(state.get_account_by_id(to).nonce.0, 1);
}
