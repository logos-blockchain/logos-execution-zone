#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    Nullifier, NullifierPublicKey, NullifierWitness, PrivacyPreservingCircuitOutput,
    PrivateWitness, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, Nonce, data::Data},
    program::{PdaSeed, PrivateAccountKind, ProgramId},
};

use super::*;
use crate::{
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{init_pda_witness, test_private_account_keys_1, test_private_account_keys_2},
    },
};

fn decrypt_kind(
    output: &PrivacyPreservingCircuitOutput,
    ssk: &SharedSecretKey,
    idx: usize,
) -> PrivateAccountKind {
    let (kind, _) = EncryptionScheme::decrypt(
        &output.private_actions[idx].encrypted_post_state.ciphertext,
        ssk,
        &output.private_actions[idx].nullifier,
    )
    .unwrap();
    kind
}

#[test]
fn proof_inner_roundtrip() {
    // `Proof::from_inner(b).into_inner()` must return exactly `b`. Catches
    // mutations of `into_inner` returning `vec![]`, `vec![0]`, or `vec![1]`,
    // and of `from_inner` discarding its argument.
    let bytes = vec![0xDE_u8, 0xAD, 0xBE, 0xEF];
    assert_eq!(Proof::from_inner(bytes.clone()).into_inner(), bytes);
    assert!(Proof::from_inner(vec![]).into_inner().is_empty());
    assert_eq!(Proof::from_inner(vec![0xFF]).into_inner(), vec![0xFF_u8]);
}

#[test]
fn prove_privacy_preserving_execution_circuit_public_and_private_pre_accounts() {
    let recipient_keys = test_private_account_keys_1();
    let program = crate::test_methods::simple_balance_transfer();
    let sender = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        AccountId::new([0; 32]),
    );

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_account_id);

    let balance_to_move: u128 = 37;

    let expected_sender_post = Account::single(
        program.id(),
        100 - balance_to_move,
        Data::default(),
        Nonce::default(),
    );

    let expected_recipient_post = Account::single(
        program.id(),
        balance_to_move,
        Data::default(),
        Nonce::private_account_nonce_init(&recipient_account_id),
    );

    let expected_sender_pre = sender.clone();

    let init_nonce = Nonce::private_account_nonce_init(&recipient_account_id);
    let esk = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk).0;

    let (output, proof) = execute_and_prove(
        vec![sender, recipient],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &crate::test_methods::simple_balance_transfer().into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let (sender_pre, sender_post) = (action.pre, action.post);
    assert_eq!(sender_pre, expected_sender_pre);
    assert_eq!(sender_post, expected_sender_post);
    assert_eq!(output.private_actions.len(), 1);

    let (_identifier, recipient_post) = EncryptionScheme::decrypt(
        &output.private_actions[0].encrypted_post_state.ciphertext,
        &shared_secret,
        &output.private_actions[0].nullifier,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_recipient_post);
}

#[test]
fn prove_privacy_preserving_execution_circuit_fully_private() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();

    let sender_nonce = Nonce(0xdead_beef);
    let sender_pre = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), sender_nonce),
        true,
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let commitment_sender = Commitment::new(&sender_account_id, &sender_pre.account);

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_account_id);
    let balance_to_move: u128 = 37;

    let mut commitment_set = CommitmentSet::with_capacity(2);
    commitment_set.extend(std::slice::from_ref(&commitment_sender));
    let expected_new_nullifiers = vec![
        (
            Nullifier::for_account_update(&commitment_sender, &sender_keys.nsk()),
            commitment_set.digest(),
        ),
        (
            Nullifier::for_account_initialization(&recipient_account_id),
            DUMMY_COMMITMENT_HASH,
        ),
    ];

    let program = crate::test_methods::simple_balance_transfer();

    let expected_private_account_1 = Account::single(
        program.id(),
        100 - balance_to_move,
        Data::default(),
        sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
    );
    let expected_private_account_2 = Account::single(
        program.id(),
        balance_to_move,
        Data::default(),
        Nonce::private_account_nonce_init(&recipient_account_id),
    );
    let expected_new_commitments = vec![
        Commitment::new(&sender_account_id, &expected_private_account_1),
        Commitment::new(&recipient_account_id, &expected_private_account_2),
    ];

    let esk_1 = EphemeralSecretKey::new(
        &sender_account_id,
        &[0; 32],
        &sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
    );
    let shared_secret_1 = SharedSecretKey::encapsulate_deterministic(&sender_keys.vpk(), &esk_1).0;

    let init_nonce_2 = Nonce::private_account_nonce_init(&recipient_account_id);
    let esk_2 = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce_2);
    let shared_secret_2 =
        SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk_2).0;

    let (output, proof) = execute_and_prove(
        vec![sender_pre, recipient],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert!(output.public_actions.is_empty());
    let sender_nullifier = expected_new_nullifiers[0].0;
    let recipient_nullifier = expected_new_nullifiers[1].0;

    let mut sorted_commitments = expected_new_commitments;
    sorted_commitments.sort_unstable_by_key(Commitment::to_byte_array);
    assert_eq!(output.commitments(), sorted_commitments);

    let mut sorted_nullifiers = expected_new_nullifiers;
    sorted_nullifiers.sort_unstable_by_key(|(nullifier, _)| nullifier.to_byte_array());
    assert_eq!(output.nullifiers(), sorted_nullifiers);

    assert_eq!(output.private_actions.len(), 2);

    let sender_slot = output
        .private_actions
        .iter()
        .position(|action| action.nullifier == sender_nullifier)
        .unwrap();
    let (_identifier, sender_post) = EncryptionScheme::decrypt(
        &output.private_actions[sender_slot]
            .encrypted_post_state
            .ciphertext,
        &shared_secret_1,
        &output.private_actions[sender_slot].nullifier,
    )
    .unwrap();
    assert_eq!(sender_post, expected_private_account_1);

    let recipient_slot = output
        .private_actions
        .iter()
        .position(|action| action.nullifier == recipient_nullifier)
        .unwrap();
    let (_identifier, recipient_post) = EncryptionScheme::decrypt(
        &output.private_actions[recipient_slot]
            .encrypted_post_state
            .ciphertext,
        &shared_secret_2,
        &output.private_actions[recipient_slot].nullifier,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_private_account_2);
}

#[test]
fn init_note_view_tag_is_derived_from_account_keys() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 0;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = AccountWithMetadata::new(Account::default(), true, account_id);

    let (output, proof) = execute_and_prove(
        vec![account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.private_actions.len(), 1);
    assert_eq!(
        output.private_actions[0].encrypted_post_state.view_tag,
        EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()),
    );
}

#[test]
fn update_note_view_tag_is_the_supplied_value() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account::single(program.id(), 1, Data::default(), Nonce::default());
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let sender = AccountWithMetadata::new(account, true, account_id);

    // A tag deliberately different from the address-derived one, so a passthrough is
    // distinguishable from re-derivation.
    let fed_tag = EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()).wrapping_add(1);

    let (output, proof) = execute_and_prove(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: fed_tag,
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.private_actions.len(), 1);
    assert_eq!(
        output.private_actions[0].encrypted_post_state.view_tag,
        fed_tag
    );
}

#[test]
fn circuit_fails_when_chained_validity_windows_have_empty_intersection() {
    let account_keys = test_private_account_keys_1();
    let pre = AccountWithMetadata::new(
        Account::default(),
        true,
        AccountId::for_regular_private_account(&account_keys.npk(), &account_keys.vpk(), 0),
    );

    let validity_window_chain_caller = crate::test_methods::validity_window_chain_caller();
    let validity_window = crate::test_methods::validity_window();

    let instruction = Program::serialize_instruction((
        Some(1_u64),
        Some(4_u64),
        validity_window.id(),
        Some(4_u64),
        Some(7_u64),
    ))
    .unwrap();

    let program_with_deps = ProgramWithDependencies::new(
        validity_window_chain_caller,
        [(validity_window.id(), validity_window)].into(),
    );

    let result = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: account_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(account_keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: account_keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// A private PDA initialized with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_init_with_custom_identifier_encrypts_correct_kind() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let binding = (program.id(), PdaSeed::new([42; 32]));
    let account_id =
        AccountId::for_private_pda(&binding.0, &binding.1, &keys.npk(), &keys.vpk(), identifier);
    let init_nonce = Nonce::private_account_nonce_init(&account_id);
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let (output, _proof) = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![init_pda_witness(&keys, identifier, binding)],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            program_id: binding.0,
            seed: binding.1,
            identifier
        },
    );
}

/// Shared regular private account: receives funds via `simple_balance_transfer` directly,
/// no custom program needed. This demonstrates the non-PDA shared account flow where
/// keys are derived from GMS via `derive_keys_for_shared_account`. The shared account
/// uses the standard foreign private account path and works with the transfer path like
/// any other private account.
#[test]
fn shared_account_receives_via_simple_transfer() {
    let program = crate::test_methods::simple_balance_transfer();
    let shared_keys = test_private_account_keys_1();
    let shared_npk = shared_keys.npk();
    let shared_identifier: u128 = 42;

    // Sender: public account with balance in the transfer program's slot
    let sender_id = AccountId::new([99; 32]);
    let sender = AccountWithMetadata::new(
        Account::single(program.id(), 1000, Data::default(), Nonce::default()),
        true,
        sender_id,
    );

    // Recipient: shared private account (new, foreign)
    let shared_account_id = AccountId::from((&shared_npk, &shared_keys.vpk(), shared_identifier));
    let recipient = AccountWithMetadata::new(Account::default(), true, shared_account_id);

    let balance_to_move: u128 = 100;
    let instruction = Program::serialize_instruction(balance_to_move).unwrap();

    let result = execute_and_prove(
        vec![sender, recipient],
        instruction,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: shared_keys.vpk(),
                random_seed: [0; 32],
                identifier: shared_identifier,
                kind: WitnessKind::Regular {
                    ask: Some(shared_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: shared_npk,
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    let (output, _proof) = result.expect("shared account receive should succeed");
    // Sender is public (no commitment), recipient is private (1 commitment)
    assert_eq!(output.private_actions.len(), 1);
}

/// A regular init with an npk derived from the held `nsk` and a non-default identifier
/// produces a ciphertext that decrypts to `PrivateAccountKind::Regular` carrying the correct
/// identifier.
#[test]
fn private_authorized_init_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&account_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let (output, _) = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: NullifierPublicKey::from(&keys.nsk()),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// A regular init with a directly-supplied npk (the caller does not own the account) and a
/// non-default identifier produces a ciphertext that decrypts to `PrivateAccountKind::Regular`
/// carrying the correct identifier.
#[test]
fn private_foreign_init_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let recipient_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &recipient_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&recipient_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_id);

    let (output, _) = execute_and_prove(
        vec![recipient],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// A regular update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_authorized_update_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::default().private_account_nonce_increment(&keys.nsk()),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let account = Account::single(program.id(), 1, Data::default(), Nonce::default());
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let sender = AccountWithMetadata::new(account, true, account_id);

    let (output, _) = execute_and_prove(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// Builds an on-chain regular private account holding balance in `program`'s slot, returning
/// its id, pre-state and a membership proof for its commitment.
fn seeded_regular_account(
    keys: &crate::state::tests::TestPrivateKeys,
    program: &Program,
    identifier: u128,
) -> (AccountId, AccountWithMetadata, lee_core::MembershipProof) {
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account::single(program.id(), 1, Data::default(), Nonce::default());
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let proof = commitment_set.get_proof_for(&commitment).unwrap();
    (
        account_id,
        AccountWithMetadata::new(account, false, account_id),
        proof,
    )
}

/// Spending without consenting. The witness carries no `ask`, so the pre-state is unauthorized,
/// and the nullifier is still produced from the `nsk`.
#[test]
fn private_regular_update_without_ask_is_spendable() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let (_, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);
    assert!(!pre.is_authorized);

    execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    )
    .unwrap();
}

/// Claiming authorization without supplying an `ask` is rejected.
#[test]
fn private_regular_witness_without_ask_cannot_assert_authorization() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let (account_id, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);
    let pre = AccountWithMetadata::new(pre.account, true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// An `ask` that does not derive this account's `nsk` is not a credential for it.
#[test]
fn regular_update_with_wrong_ask_nsk_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let (account_id, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);
    let pre = AccountWithMetadata::new(pre.account, true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(foreign.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// An `ask` that does not derive this account's `npk` is not a credential for it.
#[test]
fn regular_init_with_non_chaining_ask_npk_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(foreign.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// A program that asserts authorization over its pre-states rejects a regular private account
/// whose witness supplied no `ask`.
#[test]
fn auth_asserting_program_rejects_unauthorized_regular_private_account() {
    let program = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let (_, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

fn pda_update_binding() -> (ProgramId, PdaSeed) {
    (
        crate::test_methods::simple_balance_transfer().id(),
        PdaSeed::new([42; 32]),
    )
}

/// Root-call private-PDA update attempt: `simple_balance_transfer` moves the whole balance
/// of a PDA held in its own slot out to a public recipient.
fn pda_update_attempt(
    declare_authorized: bool,
    derivation_identifier: u128,
    witness_identifier: u128,
) -> Result<PrivacyPreservingCircuitOutput, LeeError> {
    let program = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let binding = pda_update_binding();
    let pda_id = AccountId::for_private_pda(
        &binding.0,
        &binding.1,
        &keys.npk(),
        &keys.vpk(),
        derivation_identifier,
    );
    let pda_account = Account::single(program.id(), 1, Data::default(), Nonce::default());
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let pda_pre = AccountWithMetadata::new(pda_account, declare_authorized, pda_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, AccountId::new([0; 32]));

    execute_and_prove(
        vec![pda_pre, recipient_pre],
        Program::serialize_instruction(1_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: witness_identifier,
                kind: WitnessKind::Pda { binding },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof: commitment_set.get_proof_for(&pda_commitment).unwrap(),
                },
            }),
            InputAccountIdentity::Public,
        ],
        &program.into(),
    )
    .map(|(output, _proof)| output)
}

/// A private-PDA update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_update_encrypts_pda_kind_with_identifier() {
    let keys = test_private_account_keys_1();
    let (program_id, seed) = pda_update_binding();
    let identifier: u128 = 99;

    let output = pda_update_attempt(false, identifier, identifier)
        .expect("a well-formed private PDA update must prove");

    let pda_id =
        AccountId::for_private_pda(&program_id, &seed, &keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &pda_id,
        &[0; 32],
        &Nonce::default().private_account_nonce_increment(&keys.nsk()),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Pda {
            program_id,
            seed,
            identifier
        },
    );
}

#[test]
fn private_pda_update_at_root_call_may_not_declare_authorization() {
    let result = pda_update_attempt(true, 99, 99);

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_init_identifier_mismatch_fails() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let binding = (program.id(), PdaSeed::new([42; 32]));
    let account_id =
        AccountId::for_private_pda(&binding.0, &binding.1, &keys.npk(), &keys.vpk(), 5);
    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![init_pda_witness(&keys, 99, binding)],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_init_at_root_call_may_not_declare_authorization() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 5;
    let binding = (program.id(), PdaSeed::new([42; 32]));
    let account_id =
        AccountId::for_private_pda(&binding.0, &binding.1, &keys.npk(), &keys.vpk(), identifier);
    let pre_state = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![init_pda_witness(&keys, identifier, binding)],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let result = pda_update_attempt(false, 5, 99);

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}
