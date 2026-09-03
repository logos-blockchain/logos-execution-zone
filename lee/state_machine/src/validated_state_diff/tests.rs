use std::collections::HashMap;

use lee_core::{
    account::{Account, AccountId, Data, Nonce},
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramSegment},
};

use crate::{
    PrivateKey, PublicKey, V03State,
    error::LeeError,
    public_transaction::{Message, WitnessSet},
    state::get_program_via,
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
                    program_owner: crate::test_methods::simple_balance_transfer()
                        .deployed_account_id(),
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
    let program_id = crate::test_methods::simple_balance_transfer().deployed_account_id();
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

/// Chains `elf` across as many force-inserted segments as it needs, returning the first
/// segment's `AccountId`.
fn force_insert_segment_chain(state: &mut V03State, elf: &[u8], key_seed: u8) -> AccountId {
    let chunks: Vec<&[u8]> = elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    let segment_ids: Vec<AccountId> = (0..chunks.len())
        .map(|i| {
            let mut bytes = [key_seed; 32];
            bytes[1] = u8::try_from(i).expect("chunk count fits in a u8");
            AccountId::new(bytes)
        })
        .collect();
    for i in (0..chunks.len()).rev() {
        state.force_insert_account(
            segment_ids[i],
            Account {
                program_owner: PROGRAM_LOADER_ACCOUNT_ID,
                data: Data::from(&ProgramSegment {
                    bytecode: chunks[i].to_vec(),
                    next_segment: segment_ids.get(i + 1).copied(),
                }),
                ..Account::default()
            },
        );
    }
    segment_ids[0]
}

/// A header updated only in a pending `state_diff` is seen immediately, not the stale committed
/// version.
#[test]
fn get_program_via_prefers_state_diff_over_committed_state() {
    let old_program = crate::test_methods::claimer();
    let new_program = crate::test_methods::noop();
    assert_ne!(
        old_program.id(),
        new_program.id(),
        "test needs two programs with genuinely different image_ids"
    );

    let header_id = AccountId::new([0xAA; 32]);

    let mut state = V03State::new();
    let old_segment_id = force_insert_segment_chain(&mut state, old_program.elf(), 0x01);
    state.force_insert_account(
        header_id,
        Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::from(&ProgramHeader {
                image_id: old_program.id(),
                program_first_segment: old_segment_id,
                immutable: false,
            }),
            ..Account::default()
        },
    );
    let new_segment_id = force_insert_segment_chain(&mut state, new_program.elf(), 0x02);

    // Only in the diff, as an in-progress UpdateHeader would leave it.
    let mut state_diff: HashMap<AccountId, Account> = HashMap::new();
    state_diff.insert(
        header_id,
        Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::from(&ProgramHeader {
                image_id: new_program.id(),
                program_first_segment: new_segment_id,
                immutable: false,
            }),
            ..Account::default()
        },
    );

    let (found_id, elf) = get_program_via(header_id, |id| {
        state_diff
            .get(&id)
            .cloned()
            .unwrap_or_else(|| state.get_account_by_id(id))
    })
    .expect("lookup should succeed")
    .expect("program should be found");
    assert_eq!(
        found_id,
        new_program.id(),
        "a diff-aware lookup must see the pending update"
    );
    assert_eq!(elf, new_program.elf());

    let (stale_id, stale_elf) = state
        .get_program(header_id)
        .expect("lookup should succeed")
        .expect("program should be found");
    assert_eq!(
        stale_id,
        old_program.id(),
        "state alone, with no diff, must still see only the committed version"
    );
    assert_eq!(stale_elf, old_program.elf());
}
