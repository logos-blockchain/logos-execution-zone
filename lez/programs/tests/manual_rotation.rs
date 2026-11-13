//! A manual rotation end to end: the signature guest proven privately, its `SetKey` crossing to
//! public execution, the native handler, and the applied state.

#![cfg(feature = "artifacts")]

use std::collections::BTreeMap;

use lee::{
    Account, AccountId, PrivacyPreservingTransaction, PublicAccountEvidence, PublicTransaction,
    V03State,
    privacy_preserving_transaction::{
        Message, WitnessSet,
        circuit::{ProgramCatalog, Simulation, execute_and_prove},
    },
    public_transaction,
    signature::{PublicAccountSecret, Signer, initial_key, key_state, key_state_with_counter},
    test_utils::{TestPrivateKeys, TestSigner, init_witness, no_seal, update_witness},
};
use lee_core::{
    AuthorizationSecretKey, Commitment, Nullifier, ProvingInput, RootCall, SenderPresentation,
    account::{Actor, ActorState, Nonce},
    execution_state::{BoundaryStep, PublicExecutionContext, TransactionEntry},
    signing_key::{KeyType, SigningKeyState, signature_program_id},
};
use programs::signature_program;
use signature_core::{AccountRotation, Message as SignatureGuestMessage};
use test_guest_core::Script;

/// Where the guest runs: the root actor's private account, and how it enters the proof.
enum Root {
    /// An existing private account, whose commitment the proof spends.
    Existing(Account),
    /// A fresh private account, initialized by the proof.
    Fresh,
}

fn private_keys(seed: u8) -> TestPrivateKeys {
    TestPrivateKeys {
        ask: AuthorizationSecretKey([seed; 32]),
        d: [seed.wrapping_add(1); 32],
        z: [seed.wrapping_add(2); 32],
    }
}

fn scripted_id() -> AccountId {
    AccountId::from_builtin_program(test_programs::scripted().id())
}

/// The signature guest deployed at its address, a scripted program for ordinary transactions,
/// and the root's private account if it exists.
fn state(keys: &TestPrivateKeys, root: &Root) -> V03State {
    let state = V03State::new()
        .with_programs([test_programs::scripted()])
        .with_programs_at([(signature_program_id(), signature_program(), false)]);
    match root {
        Root::Existing(account) => state.with_private_accounts([(
            Commitment::new(&keys.account_id(), account),
            Nullifier::for_account_initialization(&keys.account_id(), &keys.nsk()),
        )]),
        Root::Fresh => state,
    }
}

fn account_at(nonce: Nonce, key: SigningKeyState) -> Account {
    Account {
        nonce,
        ..Account::default()
    }
    .with_actor_state(signature_program_id(), key.into())
}

struct Proven {
    tx: PrivacyPreservingTransaction,
    root_nullifier: Nullifier,
}

/// Proves `ManualRotation` for `rotations` at the root's signature actor, with `signers` as the
/// transaction's public signers and `evidence` admitting accounts not yet in state.
fn prove(
    state: &V03State,
    keys: &TestPrivateKeys,
    root: &Root,
    rotations: &[(&PublicAccountSecret, SigningKeyState)],
    signers: &[(&TestSigner, Nonce)],
    evidence: Vec<PublicAccountEvidence>,
    presentation: SenderPresentation,
) -> Proven {
    let payer = keys.account_id();
    let targets: Vec<Actor> = rotations
        .iter()
        .map(|(secret, _)| {
            Actor::new(
                lee::signature::public_account_id(secret),
                signature_program_id(),
            )
        })
        .collect();
    let message = SignatureGuestMessage::ManualRotation {
        rotations: rotations
            .iter()
            .map(|(secret, next)| AccountRotation {
                secret: *secret.value(),
                account: lee::signature::public_account_id(secret),
                next: *next,
            })
            .collect(),
    };
    let (witness, root_nullifier) = match root {
        Root::Existing(account) => {
            let commitment = Commitment::new(&payer, account);
            let proof = state
                .get_proof_for_commitment(&commitment)
                .expect("the root's commitment is in state");
            (
                update_witness(keys, account.clone(), proof),
                Nullifier::for_account_update(&commitment, &keys.nsk()),
            )
        }
        Root::Fresh => (
            init_witness(keys),
            Nullifier::for_account_initialization(&payer, &keys.nsk()),
        ),
    };
    let (output, proof) = execute_and_prove(
        ProvingInput {
            claims: Vec::new(),
            root: TransactionEntry::Sync(RootCall {
                to: Actor::new(payer, signature_program_id()),
                message: borsh::to_vec(&message).unwrap(),
            }),
            public_context: PublicExecutionContext::new(
                targets,
                signers.iter().map(|(signer, _)| signer.account_id()),
            ),
            private_witnesses: vec![witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: std::collections::BTreeSet::new(),
            fee: None,
        },
        &Simulation::default(),
        &ProgramCatalog::from([(signature_program_id(), signature_program())]),
        |_| presentation,
        |_, _| false,
        no_seal,
    )
    .unwrap();
    let nonces: BTreeMap<AccountId, Nonce> = signers
        .iter()
        .map(|(signer, nonce)| (signer.account_id(), *nonce))
        .collect();
    let mut message = Message::from_circuit_output(nonces, output);
    message.admission_evidence = evidence;
    let signing: Vec<Signer> = signers
        .iter()
        .map(|(signer, nonce)| signer.signer(*nonce))
        .collect();
    Proven {
        tx: PrivacyPreservingTransaction::new(
            message.clone(),
            WitnessSet::sign(&message, proof, &signing),
        ),
        root_nullifier,
    }
}

/// A no-op public transaction signed by `signer` at `nonce`.
fn signed_by(signer: Signer, nonce: Nonce) -> PublicTransaction {
    let account = signer.account_id();
    let to = Actor::new(account, scripted_id());
    let message = public_transaction::Message::try_new(
        to,
        [to],
        BTreeMap::from([(account, nonce)]),
        Script::default(),
    )
    .unwrap();
    let witness = public_transaction::WitnessSet::sign(&message, &[signer]);
    PublicTransaction::new(message, witness)
}

fn stored_key(state: &V03State, account: AccountId) -> &ActorState {
    state
        .get_account_by_id_ref(account)
        .expect("the account is in state")
        .data
        .actor_state(signature_program_id())
}

fn existing_root() -> (TestPrivateKeys, Root) {
    (private_keys(13), Root::Existing(Account::funded(100)))
}

#[test]
fn manual_rotation_installs_next_without_a_nonce_bump() {
    let (keys, root) = existing_root();
    let secret = PublicAccountSecret::new([21; 32]);
    let account = lee::signature::public_account_id(&secret);
    let mut state = state(&keys, &root);
    state.force_insert_account(
        account,
        account_at(Nonce(3), key_state(&secret, KeyType::Wots, Nonce(3))),
    );
    let next = key_state_with_counter(&secret, KeyType::Wots, Nonce(3), 1);

    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&secret, next)],
        &[],
        Vec::new(),
        SenderPresentation::Canonical,
    );
    state
        .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
        .unwrap();

    assert_eq!(state.get_account_by_id(account).nonce, Nonce(3));
    assert_eq!(stored_key(&state, account), &ActorState::from(next));
    assert!(state.is_spent(&proven.root_nullifier));
}

#[test]
fn the_next_transaction_signs_with_the_manually_rotated_key() {
    for (from, to) in [
        (KeyType::Wots, KeyType::Schnorr),
        (KeyType::Schnorr, KeyType::Wots),
    ] {
        let (keys, root) = existing_root();
        let secret = PublicAccountSecret::new([22; 32]);
        let account = lee::signature::public_account_id(&secret);
        let mut state = state(&keys, &root);
        state.force_insert_account(
            account,
            account_at(Nonce(3), key_state(&secret, from, Nonce(3))),
        );
        let next = key_state_with_counter(&secret, to, Nonce(3), 1);
        let proven = prove(
            &state,
            &keys,
            &root,
            &[(&secret, next)],
            &[],
            Vec::new(),
            SenderPresentation::Canonical,
        );
        state
            .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
            .unwrap();
        assert_eq!(stored_key(&state, account), &ActorState::from(next));

        let signer = Signer::new_with_counter(&secret, Nonce(3), 1, to, KeyType::Wots);
        state
            .transition_from_public_transaction(&signed_by(signer, Nonce(3)), 2, 0)
            .expect("the manually rotated key signs");
        assert_eq!(state.get_account_by_id(account).nonce, Nonce(4));
        assert_eq!(
            stored_key(&state, account),
            &ActorState::from(key_state(&secret, KeyType::Wots, Nonce(4)))
        );
    }
}

#[test]
fn an_old_key_fails_after_a_manual_rotation() {
    let (keys, root) = existing_root();
    let secret = PublicAccountSecret::new([23; 32]);
    let account = lee::signature::public_account_id(&secret);
    let mut state = state(&keys, &root);
    state.force_insert_account(
        account,
        account_at(Nonce(3), key_state(&secret, KeyType::Wots, Nonce(3))),
    );
    let next = key_state_with_counter(&secret, KeyType::Wots, Nonce(3), 1);
    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&secret, next)],
        &[],
        Vec::new(),
        SenderPresentation::Canonical,
    );
    state
        .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
        .unwrap();

    let old = Signer::new(&secret, Nonce(3), KeyType::Wots, KeyType::Wots);
    assert!(
        state
            .transition_from_public_transaction(&signed_by(old, Nonce(3)), 2, 0)
            .is_err()
    );
    assert_eq!(state.get_account_by_id(account).nonce, Nonce(3));
}

#[test]
fn manual_rotation_at_nonce_zero() {
    let (keys, root) = existing_root();
    let secret = PublicAccountSecret::new([24; 32]);
    let account = lee::signature::public_account_id(&secret);
    let mut state = state(&keys, &root);
    let next = key_state_with_counter(&secret, KeyType::Schnorr, Nonce(0), 1);

    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&secret, next)],
        &[],
        vec![PublicAccountEvidence::Key(initial_key(&secret))],
        SenderPresentation::Canonical,
    );
    state
        .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
        .unwrap();
    assert_eq!(state.get_account_by_id(account).nonce, Nonce(0));
    assert_eq!(stored_key(&state, account), &ActorState::from(next));

    // The stored key is the current one, so the entry carries no initial-key prefix.
    let signer = Signer::new_with_counter(&secret, Nonce(0), 1, KeyType::Schnorr, KeyType::Wots);
    state
        .transition_from_public_transaction(&signed_by(signer, Nonce(0)), 2, 0)
        .expect("the manually rotated key signs at nonce 0");
    assert_eq!(state.get_account_by_id(account).nonce, Nonce(1));
}

#[test]
fn an_unadmitted_account_cannot_be_rotated() {
    let (keys, root) = existing_root();
    let secret = PublicAccountSecret::new([25; 32]);
    let mut state = state(&keys, &root);
    let next = key_state_with_counter(&secret, KeyType::Wots, Nonce(0), 1);

    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&secret, next)],
        &[],
        Vec::new(),
        SenderPresentation::Canonical,
    );

    assert!(
        state
            .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
            .is_err()
    );
    assert!(
        state
            .get_account_by_id_ref(lee::signature::public_account_id(&secret))
            .is_none()
    );
}

#[test]
fn manual_rotation_batches_two_accounts() {
    let (keys, root) = existing_root();
    let first = PublicAccountSecret::new([26; 32]);
    let second = PublicAccountSecret::new([27; 32]);
    let mut state = state(&keys, &root);
    for secret in [&first, &second] {
        state.force_insert_account(
            lee::signature::public_account_id(secret),
            account_at(Nonce(2), key_state(secret, KeyType::Wots, Nonce(2))),
        );
    }
    let next_first = key_state_with_counter(&first, KeyType::Schnorr, Nonce(2), 1);
    let next_second = key_state_with_counter(&second, KeyType::Wots, Nonce(2), 1);

    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&first, next_first), (&second, next_second)],
        &[],
        Vec::new(),
        SenderPresentation::Canonical,
    );
    state
        .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
        .unwrap();

    for (secret, next) in [(&first, next_first), (&second, next_second)] {
        let account = lee::signature::public_account_id(secret);
        assert_eq!(stored_key(&state, account), &ActorState::from(next));
        assert_eq!(state.get_account_by_id(account).nonce, Nonce(2));
    }
    assert!(state.is_spent(&proven.root_nullifier));
}

#[test]
fn a_replayed_manual_rotation_is_refused() {
    let (keys, root) = existing_root();
    let secret = PublicAccountSecret::new([28; 32]);
    let account = lee::signature::public_account_id(&secret);
    let mut state = state(&keys, &root);
    state.force_insert_account(
        account,
        account_at(Nonce(3), key_state(&secret, KeyType::Wots, Nonce(3))),
    );
    let next = key_state_with_counter(&secret, KeyType::Wots, Nonce(3), 1);
    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&secret, next)],
        &[],
        Vec::new(),
        SenderPresentation::Canonical,
    );

    state
        .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
        .unwrap();
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&proven.tx, 2, 0)
            .is_err()
    );
}

/// The public-payer mode: a fresh private account runs the guest, and a public signer is the
/// transaction's only other participant. Replay fails on the root's initialization nullifier and
/// on the signer's nonce.
#[test]
fn a_manual_rotation_with_a_fresh_private_root_and_a_public_signer() {
    let keys = private_keys(14);
    let root = Root::Fresh;
    let secret = PublicAccountSecret::new([29; 32]);
    let account = lee::signature::public_account_id(&secret);
    let payer = TestSigner::new(30);
    let mut state = state(&keys, &root);
    state.force_insert_account(
        account,
        account_at(Nonce(3), key_state(&secret, KeyType::Wots, Nonce(3))),
    );
    state.force_insert_account(
        payer.account_id(),
        Account {
            nonce: Nonce(1),
            ..Account::default()
        }
        .with_actor_state(signature_program_id(), payer.key_state(Nonce(1)).into()),
    );
    let next = key_state_with_counter(&secret, KeyType::Wots, Nonce(3), 1);

    let proven = prove(
        &state,
        &keys,
        &root,
        &[(&secret, next)],
        &[(&payer, Nonce(1))],
        Vec::new(),
        SenderPresentation::Blinded([5; 32]),
    );
    state
        .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
        .unwrap();

    assert_eq!(stored_key(&state, account), &ActorState::from(next));
    assert_eq!(state.get_account_by_id(account).nonce, Nonce(3));
    assert_eq!(state.get_account_by_id(payer.account_id()).nonce, Nonce(2));
    assert!(state.is_spent(&proven.root_nullifier));
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&proven.tx, 2, 0)
            .is_err()
    );
}

/// The signature actor sees a sender of its own program either way; a blinded presentation keeps
/// the root's private account id out of the transaction.
#[test]
fn the_disclosed_sender_is_the_signature_program() {
    for (presentation, discloses_the_root) in [
        (SenderPresentation::Canonical, true),
        (SenderPresentation::Blinded([5; 32]), false),
    ] {
        let (keys, root) = existing_root();
        let secret = PublicAccountSecret::new([31; 32]);
        let account = lee::signature::public_account_id(&secret);
        let mut state = state(&keys, &root);
        state.force_insert_account(
            account,
            account_at(Nonce(3), key_state(&secret, KeyType::Wots, Nonce(3))),
        );
        let next = key_state_with_counter(&secret, KeyType::Wots, Nonce(3), 1);
        let proven = prove(
            &state,
            &keys,
            &root,
            &[(&secret, next)],
            &[],
            Vec::new(),
            presentation,
        );

        let senders: Vec<Actor> = proven
            .tx
            .message
            .execution
            .boundary
            .iter()
            .filter_map(|step| match step {
                BoundaryStep::PrivateToPublic(delivery) => Some(delivery.envelope.from),
                _ => None,
            })
            .collect();
        assert_eq!(senders.len(), 1);
        assert_eq!(senders[0].program_account_id, signature_program_id());
        assert_eq!(
            senders[0].account_id == keys.account_id(),
            discloses_the_root
        );

        state
            .transition_from_privacy_preserving_transaction(&proven.tx, 1, 0)
            .unwrap();
        assert_eq!(stored_key(&state, account), &ActorState::from(next));
    }
}
