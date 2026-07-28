#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, EphemeralSecretKey, Nullifier,
    NullifierPublicKey, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateKind,
    PrivateWitness, SharedSecretKey,
    account::{Account, AccountId, AccountWithMetadata, Nonce, data::Data},
    program::{PdaSeed, PrivateAccountKind},
};

use super::*;
use crate::{
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{test_private_account_keys_1, test_private_account_keys_2},
    },
};

fn decrypt_kind(
    output: &PrivacyPreservingCircuitOutput,
    ssk: &SharedSecretKey,
    idx: usize,
) -> PrivateAccountKind {
    let (kind, _) = EncryptionScheme::decrypt(
        &output.encrypted_private_post_states[idx].ciphertext,
        ssk,
        &output.new_commitments[idx],
        u32::try_from(idx).expect("idx fits in u32"),
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
        Account {
            program_owner: program.id(),
            balance: 100,
            ..Account::default()
        },
        true,
        AccountId::new([0; 32]),
    );

    let recipient_account_id = recipient_keys.regular_account_id(0);
    let recipient = AccountWithMetadata::new(Account::default(), false, recipient_account_id);

    let balance_to_move: u128 = 37;

    let expected_sender_post = Account {
        program_owner: program.id(),
        balance: 100 - balance_to_move,
        nonce: Nonce::default(),
        data: Data::default(),
    };

    let expected_recipient_post = Account {
        program_owner: program.id(),
        balance: balance_to_move,
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        data: Data::default(),
    };

    let expected_sender_pre = sender.clone();

    let init_nonce = Nonce::private_account_nonce_init(&recipient_account_id);
    let esk = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk).0;

    let (output, proof) = execute_and_prove(
        vec![sender, recipient],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![PrivateWitness {
            vpk: recipient_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: recipient_keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &crate::test_methods::simple_balance_transfer().into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));

    let [sender_pre] = output.public_pre_states.try_into().unwrap();
    let [sender_post] = output.public_post_states.try_into().unwrap();
    assert_eq!(sender_pre, expected_sender_pre);
    assert_eq!(sender_post, expected_sender_post);
    assert_eq!(output.new_commitments.len(), 1);
    assert_eq!(output.new_nullifiers.len(), 1);
    assert_eq!(output.encrypted_private_post_states.len(), 1);

    let (_identifier, recipient_post) = EncryptionScheme::decrypt(
        &output.encrypted_private_post_states[0].ciphertext,
        &shared_secret,
        &output.new_commitments[0],
        0,
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
        Account {
            balance: 100,
            nonce: sender_nonce,
            program_owner: program.id(),
            data: Data::default(),
        },
        true,
        sender_keys.regular_account_id(0),
    );
    let sender_account_id = sender_keys.regular_account_id(0);
    let sender_account = sender_pre.account.clone();
    let commitment_sender = Commitment::new(&sender_account_id, &sender_pre.account);

    let recipient_account_id = recipient_keys.regular_account_id(0);
    let recipient = AccountWithMetadata::new(Account::default(), false, recipient_account_id);
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

    let expected_private_account_1 = Account {
        program_owner: program.id(),
        balance: 100 - balance_to_move,
        nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ..Default::default()
    };
    let expected_private_account_2 = Account {
        program_owner: program.id(),
        balance: balance_to_move,
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        ..Default::default()
    };
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
            PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: PrivateKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    nsk: sender_keys.nsk(),
                    membership_proof: commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                    pre_account: sender_account,
                },
            },
            PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: PrivateKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            },
        ],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert!(output.public_pre_states.is_empty());
    assert!(output.public_post_states.is_empty());
    assert_eq!(output.new_commitments, expected_new_commitments);
    assert_eq!(output.new_nullifiers, expected_new_nullifiers);
    assert_eq!(output.encrypted_private_post_states.len(), 2);

    let (_identifier, sender_post) = EncryptionScheme::decrypt(
        &output.encrypted_private_post_states[0].ciphertext,
        &shared_secret_1,
        &expected_new_commitments[0],
        0,
    )
    .unwrap();
    assert_eq!(sender_post, expected_private_account_1);

    let (_identifier, recipient_post) = EncryptionScheme::decrypt(
        &output.encrypted_private_post_states[1].ciphertext,
        &shared_secret_2,
        &expected_new_commitments[1],
        1,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_private_account_2);
}

#[test]
fn circuit_fails_when_chained_validity_windows_have_empty_intersection() {
    let account_keys = test_private_account_keys_1();
    let pre = AccountWithMetadata::new(
        Account::default(),
        false,
        account_keys.regular_account_id(0),
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
        vec![PrivateWitness {
            vpk: account_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: account_keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// A private PDA claimed with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_claim_with_custom_identifier_encrypts_correct_kind() {
    let program = crate::test_methods::pda_claimer();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 99;
    let account_id = keys.pda_account_id(&program.id(), &seed, identifier);
    let init_nonce = Nonce::private_account_nonce_init(&account_id);
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let (output, _proof) = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(seed).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: PrivateKind::Pda {
                seed: (seed, program.id()),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program.clone().into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            program_id: program.id(),
            seed,
            identifier
        },
    );
}

/// PDA init: initializes a new PDA under `simple_balance_transfer`'s ownership.
/// The `simple_transfer_proxy` program chains to `simple_balance_transfer` with `pda_seeds`
/// to establish authorization and the private PDA binding.
#[test]
fn private_pda_init() {
    let program = crate::test_methods::simple_transfer_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let program_id = program.id();
    // PDA (new, private PDA)
    let pda_id = keys.pda_account_id(&program_id, &seed, 0);
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

    let auth_id = simple_transfer.id();
    let program_with_deps =
        ProgramWithDependencies::new(program, [(auth_id, simple_transfer)].into());

    // is_withdraw=false triggers init path (1 pre-state)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, false)).unwrap();

    let result = execute_and_prove(
        vec![pda_pre],
        instruction,
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Pda {
                seed: (seed, program_id),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA init should succeed");
    assert_eq!(output.new_commitments.len(), 1);
}

/// PDA withdraw: chains to `simple_balance_transfer` to move balance from PDA to recipient.
/// Uses a default PDA (amount=0) because testing with a pre-funded PDA requires a
/// two-tx sequence with membership proofs.
#[test]
fn private_pda_withdraw() {
    let program = crate::test_methods::simple_transfer_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let program_id = program.id();
    // PDA (new, private PDA)
    let pda_id = keys.pda_account_id(&program_id, &seed, 0);
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

    // Recipient (public)
    let recipient_id = AccountId::new([88; 32]);
    let recipient_pre = AccountWithMetadata::new(
        Account {
            program_owner: simple_transfer.id(),
            balance: 10000,
            ..Account::default()
        },
        true,
        recipient_id,
    );

    let auth_id = simple_transfer.id();
    let program_with_deps =
        ProgramWithDependencies::new(program, [(auth_id, simple_transfer)].into());

    // is_withdraw=true, amount=0 (PDA has no balance yet)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, true)).unwrap();

    let result = execute_and_prove(
        vec![pda_pre, recipient_pre],
        instruction,
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Pda {
                seed: (seed, program_id),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA withdraw should succeed");
    assert_eq!(output.new_commitments.len(), 1);
}

/// Shared regular private account: receives funds via `authenticated_transfer` directly,
/// no custom program needed. This demonstrates the non-PDA shared account flow where
/// keys are derived from GMS via `derive_keys_for_shared_account`. The shared account
/// uses the standard unauthorized private account path and works with auth-transfer's
/// transfer path like any other private account.
#[test]
fn shared_account_receives_via_simple_transfer() {
    let program = crate::test_methods::simple_balance_transfer();
    let shared_keys = test_private_account_keys_1();
    let shared_npk = shared_keys.npk();
    let shared_identifier: u128 = 42;

    // Sender: public account with balance, owned by auth-transfer
    let sender_id = AccountId::new([99; 32]);
    let sender = AccountWithMetadata::new(
        Account {
            program_owner: program.id(),
            balance: 1000,
            ..Account::default()
        },
        true,
        sender_id,
    );

    // Recipient: shared private account (new, unauthorized)
    let shared_account_id = shared_keys.regular_account_id(shared_identifier);
    let recipient = AccountWithMetadata::new(Account::default(), false, shared_account_id);

    let balance_to_move: u128 = 100;
    let instruction = Program::serialize_instruction(balance_to_move).unwrap();

    let result = execute_and_prove(
        vec![sender, recipient],
        instruction,
        vec![PrivateWitness {
            vpk: shared_keys.vpk(),
            random_seed: [0; 32],
            identifier: shared_identifier,
            kind: PrivateKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: shared_npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program.into(),
    );

    let (output, _proof) = result.expect("shared account receive should succeed");
    // Sender is public (no commitment), recipient is private (1 commitment)
    assert_eq!(output.new_commitments.len(), 1);
}

/// An authorized regular init with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_authorized_init_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::claimer();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = keys.regular_account_id(identifier);
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
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: PrivateKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: NullifierPublicKey::from(&keys.nsk()),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// An unauthorized regular init with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_unauthorized_init_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::claimer();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let recipient_id = keys.regular_account_id(identifier);
    let esk = EphemeralSecretKey::new(
        &recipient_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&recipient_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let recipient = AccountWithMetadata::new(Account::default(), false, recipient_id);

    let (output, _) = execute_and_prove(
        vec![recipient],
        Program::serialize_instruction(()).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: PrivateKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// An authorized regular update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_authorized_update_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = keys.regular_account_id(identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::default().private_account_nonce_increment(&keys.nsk()),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let account = Account {
        program_owner: program.id(),
        balance: 1,
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let sender = AccountWithMetadata::new(account.clone(), true, account_id);

    let (output, _) = execute_and_prove(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: PrivateKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
                pre_account: account,
            },
        }],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// A private PDA update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_update_encrypts_pda_kind_with_identifier() {
    let program = crate::test_methods::pda_spend_delegator();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 99;
    let simple_transfer_id = simple_transfer.id();
    let program_id = program.id();
    let pda_id = keys.pda_account_id(&program_id, &seed, identifier);
    let esk = EphemeralSecretKey::new(
        &pda_id,
        &[0; 32],
        &Nonce::default().private_account_nonce_increment(&keys.nsk()),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let pda_account = Account {
        program_owner: simple_transfer_id,
        balance: 1,
        ..Account::default()
    };
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let pda_pre = AccountWithMetadata::new(pda_account.clone(), false, pda_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, AccountId::new([0; 32]));

    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        [(simple_transfer_id, simple_transfer)].into(),
    );

    let (output, _) = execute_and_prove(
        vec![pda_pre, recipient_pre],
        Program::serialize_instruction((seed, 1_u128, simple_transfer_id)).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: PrivateKind::Pda {
                seed: (seed, program_id),
            },
            nullifier: NullifierWitness::Update {
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&pda_commitment).unwrap(),
                pre_account: pda_account,
            },
        }],
        &program_with_deps,
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Pda {
            program_id: program.id(),
            seed,
            identifier
        },
    );
}

#[test]
fn private_pda_init_identifier_mismatch_fails() {
    let program = crate::test_methods::pda_claimer();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id = keys.pda_account_id(&program.id(), &seed, 5);
    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(seed).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 99,
            kind: PrivateKind::Pda {
                seed: (seed, program.id()),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let program = crate::test_methods::pda_spend_delegator();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let simple_transfer_id = simple_transfer.id();
    let program_id = program.id();
    let pda_id = keys.pda_account_id(&program_id, &seed, 5);
    let pda_account = Account {
        program_owner: simple_transfer_id,
        balance: 1,
        ..Account::default()
    };
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let pda_pre = AccountWithMetadata::new(pda_account.clone(), false, pda_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, AccountId::new([0; 32]));

    let program_with_deps =
        ProgramWithDependencies::new(program, [(simple_transfer_id, simple_transfer)].into());

    let result = execute_and_prove(
        vec![pda_pre, recipient_pre],
        Program::serialize_instruction((seed, 1_u128, simple_transfer_id)).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 99,
            kind: PrivateKind::Pda {
                seed: (seed, program_id),
            },
            nullifier: NullifierWitness::Update {
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&pda_commitment).unwrap(),
                pre_account: pda_account,
            },
        }],
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

// A.4 regression: pda_spend_proxy demands its root PDA pre_state be authorized — the private-only
// relaxation this change closes. A root PDA supplied is_authorized=true is now rejected by the
// uniform check on the private path, as a PDA always was on the public path (never a root signer).
#[test]
fn pda_spend_proxy_at_root_is_rejected() {
    let program = crate::test_methods::pda_spend_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let simple_transfer_id = simple_transfer.id();
    let program_id = program.id();
    let pda_id = keys.pda_account_id(&program_id, &seed, 0);
    let pda_account = Account {
        program_owner: simple_transfer_id,
        balance: 1,
        ..Account::default()
    };
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let pda_pre = AccountWithMetadata::new(pda_account.clone(), true, pda_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, AccountId::new([0; 32]));

    let program_with_deps =
        ProgramWithDependencies::new(program, [(simple_transfer_id, simple_transfer)].into());

    let result = execute_and_prove(
        vec![pda_pre, recipient_pre],
        Program::serialize_instruction((seed, 1_u128, simple_transfer_id)).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Pda {
                seed: (seed, program_id),
            },
            nullifier: NullifierWitness::Update {
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&pda_commitment).unwrap(),
                pre_account: pda_account,
            },
        }],
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

// Gate for removing the in-guest regular is_authorized<=>Held assert (output.rs): the shared
// uniform check alone must reject a regular private account claiming authorization
// (is_authorized=true) without holding its auth key (`ask: None`).
#[test]
fn regular_authorized_without_held_key_is_rejected() {
    let account_keys = test_private_account_keys_1();
    let pre =
        AccountWithMetadata::new(Account::default(), true, account_keys.regular_account_id(0));

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![PrivateWitness {
            vpk: account_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: account_keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }],
        &crate::test_methods::noop().into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

// Gate for the chain check in `PrivateBackend::new`: a regular account id commits only `npk`, so
// `npk == KDF(KDF(ask))` is the sole binding between an id and an authorization credential. A
// well-formed but non-chaining `ask` must not authorize an account whose `npk` the prover merely
// knows — the check is verified against the same row's nullifier witness.
#[test]
fn regular_update_with_non_chaining_ask_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let account_id = keys.regular_account_id(0);
    let account = Account {
        program_owner: program.id(),
        balance: 1,
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let sender = AccountWithMetadata::new(account.clone(), true, account_id);

    let result = execute_and_prove(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: PrivateKind::Regular {
                ask: Some([99; 32]),
            },
            nullifier: NullifierWitness::Update {
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
                pre_account: account,
            },
        }],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}
