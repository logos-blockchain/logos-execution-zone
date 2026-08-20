use std::collections::HashMap;

use lee_core::account::{Account, AccountId, Nonce};

use crate::{
    PrivateKey, PublicKey, V03State,
    error::LeeError,
    program::Program,
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

// Three tests previously lived here (`privacy_malicious_programs_cannot_drain_public_victim`,
// `privacy_malicious_programs_cannot_drain_private_victim`,
// `malicious_programs_cannot_drain_victim_without_signature`), each proving that a chained call
// couldn't fabricate a victim's account value and forge `is_authorized=true` for it, on both
// execution paths. That attack — demonstrated via the now-deleted `malicious_injector`/
// `malicious_launderer` guest programs — relied on `ChainedCall` carrying a full
// caller-supplied `AccountWithMetadata`. Since `ChainedCall.pre_state_refs` now carries only
// `AccountId`s, with the account's value and authorization always resolved by the protocol from
// its own tracked state, there's no longer a channel through which a program could supply a
// fabricated value at all — this attack class is a compile-time impossibility, not something a
// runtime check needs to keep catching.

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
        public_diffs: vec![],
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
        signer_account_ids: vec![],
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

/// The race condition this whole `AccountDiff` design fixes: a public account changes on-chain
/// after proving but before sequencer validation (e.g. an unrelated transfer lands first). Proof
/// validity no longer depends on a snapshot — only on what the circuit witnessed — so the proof
/// still verifies, and its diff replays against the live balance at validation time, not the
/// stale one captured while proving.
#[test]
fn privacy_transaction_survives_public_state_changing_after_proving() {
    use lee_core::{
        DUMMY_COMMITMENT_HASH, InputAccountIdentity, NullifierWitness, PrivateWitness, WitnessKind,
        account::AccountWithMetadata,
    };

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::execute_and_prove, message::Message, witness_set::WitnessSet,
        },
        state::tests::test_private_account_keys_1,
    };

    let program = crate::test_methods::simple_balance_transfer();
    let recipient_keys = test_private_account_keys_1();

    let sender_key = PrivateKey::try_new([3_u8; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let balance_at_proving_time = 100_u128;
    let balance_to_move = 37_u128;

    // State as it looked when the prover captured its pre-state.
    let state_at_proving_time = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(
            sender_id,
            balance_at_proving_time,
        )]))
        .with_programs(std::iter::once(program.clone()));

    let sender_pre = AccountWithMetadata::new(
        state_at_proving_time.get_account_by_id(sender_id),
        true,
        sender_id,
    );

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient_pre = AccountWithMetadata::new(Account::default(), false, recipient_account_id);

    let (circuit_output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    )
    .expect("execute_and_prove should succeed");

    let message = Message::from_circuit_output(vec![Nonce(0)], circuit_output);
    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    // Simulates an unrelated public transaction landing on the sender's account between
    // proving and sequencer validation: live state now disagrees with what the prover
    // witnessed as `sender_pre`.
    let balance_at_validation_time = 250_u128;
    let state_at_validation_time = state_at_proving_time.with_public_accounts(
        public_state_from_balances(&[(sender_id, balance_at_validation_time)]),
    );

    let diff = ValidatedStateDiff::from_privacy_preserving_transaction(
        &tx,
        &state_at_validation_time,
        1,
        0,
    )
    .expect(
        "proof validity must not depend on live public state matching the witnessed \
                 pre-state",
    );
    let public_diff = diff.public_diff();

    assert_eq!(
        public_diff[&sender_id].balance,
        balance_at_validation_time - balance_to_move,
        "the diff must be replayed against live state at validation time, not the stale \
         balance captured when the proof was generated",
    );
}
