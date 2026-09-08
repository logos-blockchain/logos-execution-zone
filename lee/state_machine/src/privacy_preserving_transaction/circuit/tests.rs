#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    Nullifier, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateWitness, SharedSecretKey,
    WitnessKind,
    account::{Account, AccountData, AccountId, Nonce},
    program::{PdaSeed, PrivateAccountKind},
};

use super::*;
use crate::{
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{
            init_pda_witness, init_witness, test_private_account_keys_1,
            test_private_account_keys_2, update_pda_witness, update_witness,
        },
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
    let sender_id = AccountId::new([0; 32]);
    let sender_account = Account::funded(100);

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let balance_to_move: u128 = 37;

    let expected_sender_pre = AccountData {
        balance: 100,
        ..AccountData::default()
    };
    let expected_sender_post = AccountData {
        balance: 100 - balance_to_move,
        ..AccountData::default()
    };

    let expected_recipient_post = Account {
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        ..Account::funded(balance_to_move)
    };

    let init_nonce = Nonce::private_account_nonce_init(&recipient_account_id);
    let esk = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk).0;

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_account_id),
            ],
            signers: [sender_id].into(),
            public_accounts: [(sender_id, sender_account)].into(),
            private_witnesses: vec![init_witness(&recipient_keys, 0, Account::default())],
            instruction_data: Program::serialize_instruction(balance_to_move).unwrap(),
            ..Default::default()
        },
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    assert_eq!(action.account_id, sender_id);
    assert!(action.is_authorized);
    assert_eq!(action.pre, expected_sender_pre);
    assert_eq!(action.post, expected_sender_post);
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
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_pre_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let commitment_sender = Commitment::new(&sender_account_id, &sender_pre_account);

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
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

    let expected_private_account_1 = Account {
        nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ..Account::funded(100 - balance_to_move)
    };
    let expected_private_account_2 = Account {
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        ..Account::funded(balance_to_move)
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
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_account_id),
                ProgramShardSelector::balance_only(recipient_account_id),
            ],
            private_witnesses: vec![
                update_witness(
                    &sender_keys,
                    0,
                    sender_pre_account,
                    commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                ),
                init_witness(&recipient_keys, 0, Account::default()),
            ],
            instruction_data: Program::serialize_instruction(balance_to_move).unwrap(),
            ..Default::default()
        },
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

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_witness(&keys, identifier, Account::default())],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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
    let account = Account::funded(1);
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    // A tag deliberately different from the address-derived one, so a passthrough is
    // distinguishable from re-derivation.
    let fed_tag = EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()).wrapping_add(1);

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![PrivateWitness {
                account,
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
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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
    let account_id =
        AccountId::for_regular_private_account(&account_keys.npk(), &account_keys.vpk(), 0);

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
        validity_window_chain_caller.clone(),
        validity_window_chain_caller.id().into(),
        [(validity_window.id().into(), validity_window)].into(),
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_witness(&account_keys, 0, Account::default())],
            instruction_data: instruction,
            ..Default::default()
        },
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// A private PDA bound with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_with_custom_identifier_encrypts_correct_kind() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 99;
    let account_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        identifier,
    );
    let init_nonce = Nonce::private_account_nonce_init(&account_id);
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                identifier,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.clone().into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            account_id: program.id().into(),
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
    // PDA (new, private PDA)
    let pda_id =
        AccountId::for_private_pda(&AccountId::from(program.id()), &seed, &npk, &keys.vpk(), 0);

    let auth_id: AccountId = simple_transfer.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(auth_id, simple_transfer)].into(),
    );

    // is_withdraw=false triggers init path (1 pre-state)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, false)).unwrap();

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(pda_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: instruction,
            ..Default::default()
        },
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA init should succeed");
    assert_eq!(output.private_actions.len(), 1);
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
    // PDA (new, private PDA)
    let pda_id =
        AccountId::for_private_pda(&AccountId::from(program.id()), &seed, &npk, &keys.vpk(), 0);

    // Recipient (public)
    let recipient_id = AccountId::new([88; 32]);
    let recipient_account = Account::funded(10000);

    let auth_id: AccountId = simple_transfer.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(auth_id, simple_transfer)].into(),
    );

    // is_withdraw=true, amount=0 (PDA has no balance yet)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, true)).unwrap();

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(pda_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            signers: [recipient_id].into(),
            public_accounts: [(recipient_id, recipient_account)].into(),
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: instruction,
            ..Default::default()
        },
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA withdraw should succeed");
    assert_eq!(output.private_actions.len(), 1);
}

/// Shared regular private account: receives funds via `authenticated_transfer` directly,
/// no custom program needed. This demonstrates the non-PDA shared account flow where
/// keys are derived from GMS via `derive_keys_for_shared_account`. The shared account
/// uses the standard foreign private account path and works with auth-transfer's
/// transfer path like any other private account.
#[test]
fn shared_account_receives_via_simple_transfer() {
    let program = crate::test_methods::simple_balance_transfer();
    let shared_keys = test_private_account_keys_1();
    let shared_npk = shared_keys.npk();
    let shared_identifier: u128 = 42;

    // Sender: public account with balance, owned by auth-transfer
    let sender_id = AccountId::new([99; 32]);
    let sender_account = Account::funded(1000);

    // Recipient: shared private account (new, foreign)
    let shared_account_id = AccountId::from((&shared_npk, &shared_keys.vpk(), shared_identifier));

    let balance_to_move: u128 = 100;
    let instruction = Program::serialize_instruction(balance_to_move).unwrap();

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(shared_account_id),
            ],
            signers: [sender_id].into(),
            public_accounts: [(sender_id, sender_account)].into(),
            private_witnesses: vec![init_witness(
                &shared_keys,
                shared_identifier,
                Account::default(),
            )],
            instruction_data: instruction,
            ..Default::default()
        },
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

    let (output, _) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_witness(&keys, identifier, Account::default())],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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

    let (output, _) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(recipient_id)],
            private_witnesses: vec![init_witness(&keys, identifier, Account::default())],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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
    let account = Account::funded(1);
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let (output, _) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![update_witness(
                &keys,
                identifier,
                account,
                commitment_set.get_proof_for(&commitment).unwrap(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// Builds a regular private account, returning its id, pre-state and a membership proof for its
/// commitment.
fn seeded_regular_account(
    keys: &crate::state::tests::TestPrivateKeys,
    identifier: u128,
) -> (AccountId, Account, lee_core::MembershipProof) {
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account::funded(1);
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let proof = commitment_set.get_proof_for(&commitment).unwrap();
    (account_id, account, proof)
}

/// Spending without consenting. The witness carries no `ask`, so the pre-state is unauthorized,
/// and the nullifier is still produced from the `nsk`.
#[test]
fn private_regular_update_without_ask_is_spendable() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, 0);

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![PrivateWitness {
                account,
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    )
    .unwrap();
}

#[test]
fn private_regular_witness_without_ask_cannot_assert_authorization() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            signers: [account_id].into(),
            private_witnesses: vec![PrivateWitness {
                account,
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![PrivateWitness {
                account,
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
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![PrivateWitness {
                account: Account::default(),
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
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
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
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![PrivateWitness {
                account,
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

/// Root-call private-PDA update attempt: `pda_spend_proxy` spends a PDA it owns via
/// `simple_balance_transfer`.
fn pda_update_attempt(
    declare_authorized: bool,
    derivation_identifier: u128,
    witness_identifier: u128,
) -> Result<lee_core::PrivacyPreservingCircuitOutput, LeeError> {
    let program = crate::test_methods::pda_spend_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let simple_transfer_id: AccountId = simple_transfer.id().into();
    let program_id: AccountId = program.id().into();
    let pda_id = AccountId::for_private_pda(
        &program_id,
        &seed,
        &keys.npk(),
        &keys.vpk(),
        derivation_identifier,
    );
    let pda_account = Account::funded(1);
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let recipient_id = AccountId::new([0; 32]);
    let mut signers = HashSet::from([recipient_id]);
    if declare_authorized {
        signers.insert(pda_id);
    }

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_id,
        [(simple_transfer_id, simple_transfer)].into(),
    );

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(pda_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            signers,
            public_accounts: [
                (pda_id, pda_account.clone()),
                (recipient_id, Account::default()),
            ]
            .into(),
            private_witnesses: vec![update_pda_witness(
                &keys,
                witness_identifier,
                (program_id, seed),
                pda_account,
                commitment_set.get_proof_for(&pda_commitment).unwrap(),
            )],
            instruction_data: Program::serialize_instruction((seed, 1_u128, simple_transfer_id))
                .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .map(|(output, _proof)| output)
}

/// A private-PDA update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_update_encrypts_pda_kind_with_identifier() {
    let program_id: AccountId = crate::test_methods::pda_spend_proxy().id().into();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
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
            account_id: program_id,
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
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id =
        AccountId::for_private_pda(&AccountId::from(program.id()), &seed, &npk, &keys.vpk(), 5);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                99,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_init_at_root_call_may_not_declare_authorization() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 5;
    let account_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        identifier,
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            signers: [account_id].into(),
            private_witnesses: vec![init_pda_witness(
                &keys,
                identifier,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let result = pda_update_attempt(false, 5, 99);

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

fn forwarder_over_callee() -> (ProgramWithDependencies, AccountId, AccountId) {
    let forwarder = crate::test_methods::shard_forwarder();
    let callee = crate::test_methods::data_changer();
    let forwarder_id: AccountId = forwarder.id().into();
    let callee_id: AccountId = callee.id().into();

    (
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into()),
        forwarder_id,
        callee_id,
    )
}

fn forwarder_instruction(
    own_write: Option<(AccountId, &[u8])>,
    calls: &[(AccountId, ProgramShardSelector, Vec<u8>)],
) -> Vec<u8> {
    Program::serialize_instruction((
        own_write.map(|(target, bytes)| (target, bytes.to_vec())),
        calls.to_vec(),
    ))
    .unwrap()
}

fn calls_at(
    account_id: AccountId,
    calls: &[(AccountId, Vec<u8>)],
) -> Vec<(AccountId, ProgramShardSelector, Vec<u8>)> {
    calls
        .iter()
        .map(|(callee, instruction)| {
            (
                *callee,
                ProgramShardSelector::new(account_id, *callee),
                instruction.clone(),
            )
        })
        .collect()
}

fn data_changer_instruction(write: &[u8]) -> Vec<u8> {
    Program::serialize_instruction(write.to_vec()).unwrap()
}

fn forward_to(account_id: AccountId, callee_id: AccountId, write: &[u8]) -> Vec<u8> {
    forwarder_instruction(
        None,
        &calls_at(account_id, &[(callee_id, data_changer_instruction(write))]),
    )
}

fn input_with(
    account_id: AccountId,
    forwarder_id: AccountId,
    account: Account,
    instruction_data: Vec<u8>,
) -> ProvingInput {
    ProvingInput {
        shard_selectors: vec![ProgramShardSelector::new(account_id, forwarder_id)],
        public_accounts: [(account_id, account)].into(),
        instruction_data,
        ..Default::default()
    }
}

fn forwarding_input(
    account_id: AccountId,
    forwarder_id: AccountId,
    callee_id: AccountId,
    account: Account,
    write: &[u8],
) -> ProvingInput {
    input_with(
        account_id,
        forwarder_id,
        account,
        forward_to(account_id, callee_id, write),
    )
}

#[test]
fn a_resolver_supplies_a_chained_calls_unfetched_shard_and_matches_the_complete_account() {
    let (program, forwarder_id, callee_id) = forwarder_over_callee();
    let account_id = AccountId::new([7; 32]);
    let balance = 500;
    let on_chain = Data::try_from(vec![1; 8]).unwrap();
    let own_shard = Data::try_from(vec![2; 8]).unwrap();
    let write = vec![3; 16];

    let sparse = Account::funded(balance).with_shard(forwarder_id, own_shard.clone());
    let complete = sparse.clone().with_shard(callee_id, on_chain.clone());

    let mut asked: Vec<ProgramShardSelector> = Vec::new();
    let (output, proof) = execute_and_prove_with(
        forwarding_input(account_id, forwarder_id, callee_id, sparse.clone(), &write),
        &program,
        &mut |shard_selector| {
            asked.push(shard_selector);
            Ok(Some(on_chain.clone()))
        },
    )
    .unwrap();

    assert_eq!(
        asked,
        vec![ProgramShardSelector::new(account_id, callee_id)]
    );
    assert!(proof.is_valid_for(&output));

    let [action] = &*output.public_actions else {
        panic!("one account, one action: {:?}", output.public_actions)
    };
    assert_eq!(action.account_id, account_id);
    assert_eq!(action.pre.balance, balance);
    assert_eq!(action.pre.shards[&forwarder_id], own_shard);
    assert_eq!(action.pre.shards[&callee_id], on_chain);
    assert_eq!(action.post.balance, balance);
    assert_eq!(
        action.post.shards[&callee_id],
        Data::try_from(write.clone()).unwrap()
    );

    let (complete_output, _) = execute_and_prove(
        forwarding_input(account_id, forwarder_id, callee_id, complete, &write),
        &program,
    )
    .unwrap();
    assert_eq!(output, complete_output);

    let (unresolved_output, _) = execute_and_prove(
        forwarding_input(account_id, forwarder_id, callee_id, sparse, &write),
        &program,
    )
    .unwrap();
    assert_ne!(unresolved_output, complete_output);
}

#[test]
fn resolving_an_empty_shard_matches_not_resolving_at_all() {
    let (program, forwarder_id, callee_id) = forwarder_over_callee();
    let account_id = AccountId::new([7; 32]);
    let write = vec![3; 16];

    let sparse = Account::funded(500).with_shard(forwarder_id, Data::try_from(vec![2; 8]).unwrap());

    let (unresolved_output, _) = execute_and_prove(
        forwarding_input(account_id, forwarder_id, callee_id, sparse.clone(), &write),
        &program,
    )
    .unwrap();

    let mut asked = 0_u32;
    let (resolved_output, _) = execute_and_prove_with(
        forwarding_input(account_id, forwarder_id, callee_id, sparse, &write),
        &program,
        &mut |_| {
            asked += 1;
            Ok(Some(Data::empty()))
        },
    )
    .unwrap();

    assert_eq!(asked, 1);
    assert_eq!(resolved_output, unresolved_output);
}

#[test]
fn a_resolver_error_aborts_the_traversal() {
    let (program, forwarder_id, callee_id) = forwarder_over_callee();
    let account_id = AccountId::new([7; 32]);

    let result = execute_and_prove_with(
        forwarding_input(
            account_id,
            forwarder_id,
            callee_id,
            Account::default(),
            &[3; 16],
        ),
        &program,
        &mut |_| {
            Err(LeeError::AccountResolution(
                "sequencer unreachable".to_owned(),
            ))
        },
    );

    assert!(matches!(result, Err(LeeError::AccountResolution(_))));
}

fn forwarder_over_itself() -> (ProgramWithDependencies, AccountId) {
    let forwarder = crate::test_methods::shard_forwarder();
    let forwarder_id: AccountId = forwarder.id().into();

    (
        ProgramWithDependencies::new(
            forwarder.clone(),
            forwarder_id,
            [(forwarder_id, forwarder)].into(),
        ),
        forwarder_id,
    )
}

#[test]
fn a_top_level_shard_selector_is_never_resolved_for() {
    let (program, forwarder_id) = forwarder_over_itself();
    let account_id = AccountId::new([7; 32]);
    let supplied = Data::try_from(vec![0xA1; 12]).unwrap();

    let instruction = forwarder_instruction(
        None,
        &calls_at(
            account_id,
            &[(forwarder_id, forwarder_instruction(None, &[]))],
        ),
    );

    let mut asked: Vec<ProgramShardSelector> = Vec::new();
    let (output, proof) = execute_and_prove_with(
        input_with(
            account_id,
            forwarder_id,
            Account::default().with_shard(forwarder_id, supplied.clone()),
            instruction,
        ),
        &program,
        &mut |shard_selector| {
            asked.push(shard_selector);
            Ok(Some(Data::try_from(vec![0xEE; 12]).unwrap()))
        },
    )
    .unwrap();

    assert!(
        asked.is_empty(),
        "the only shard selector this transaction touches came from the caller: {asked:?}"
    );
    assert!(proof.is_valid_for(&output));

    let [action] = <[_; 1]>::try_from(output.public_actions).unwrap();
    assert_eq!(
        action.post.shards[&forwarder_id], supplied,
        "the chained call must have run against the supplied value, not the resolver's"
    );
}

#[test]
fn a_shard_selector_is_resolved_at_most_once_across_chained_calls() {
    let (program, forwarder_id, callee_id) = forwarder_over_callee();
    let account_id = AccountId::new([7; 32]);
    let first = vec![0xC1; 12];
    let second = vec![0xC2; 12];

    let instruction = forwarder_instruction(
        None,
        &calls_at(
            account_id,
            &[
                (callee_id, data_changer_instruction(&first)),
                (callee_id, data_changer_instruction(&second)),
            ],
        ),
    );

    let mut asked: Vec<ProgramShardSelector> = Vec::new();
    let (output, _proof) = execute_and_prove_with(
        input_with(account_id, forwarder_id, Account::default(), instruction),
        &program,
        &mut |shard_selector| {
            asked.push(shard_selector);
            Ok(Some(Data::empty()))
        },
    )
    .unwrap();

    assert_eq!(
        asked,
        vec![ProgramShardSelector::new(account_id, callee_id)]
    );

    let [action] = <[_; 1]>::try_from(output.public_actions).unwrap();
    assert_eq!(
        action.post.shards[&callee_id],
        Data::try_from(second).unwrap()
    );
}

#[test]
fn a_write_at_an_account_nothing_handed_the_root_is_never_resolved_over() {
    let forwarder = crate::test_methods::shard_forwarder();
    let echo = crate::test_methods::noop();
    let forwarder_id: AccountId = forwarder.id().into();
    let echo_id: AccountId = echo.id().into();
    let program = ProgramWithDependencies::new(forwarder, forwarder_id, [(echo_id, echo)].into());

    let account_id = AccountId::new([7; 32]);
    let fresh_id = AccountId::new([8; 32]);
    let written = vec![0xA1; 12];

    let instruction = forwarder_instruction(
        Some((fresh_id, &written)),
        &[(
            echo_id,
            ProgramShardSelector::new(fresh_id, forwarder_id),
            Program::serialize_instruction(()).unwrap(),
        )],
    );

    let mut asked: Vec<ProgramShardSelector> = Vec::new();
    let (output, proof) = execute_and_prove_with(
        input_with(account_id, forwarder_id, Account::default(), instruction),
        &program,
        &mut |shard_selector| {
            asked.push(shard_selector);
            Ok(Some(Data::try_from(vec![0xEE; 12]).unwrap()))
        },
    )
    .unwrap();

    assert!(
        !asked.contains(&ProgramShardSelector::new(fresh_id, forwarder_id)),
        "the root's own write covers the shard selector; fetching for it would drop that write: \
         {asked:?}"
    );
    assert!(proof.is_valid_for(&output));

    let fresh = output
        .public_actions
        .iter()
        .find(|action| action.account_id == fresh_id)
        .expect("the fresh account must appear in the journal");
    assert_eq!(
        fresh.post.shards[&forwarder_id],
        Data::try_from(written).unwrap(),
        "the callee must have run against the root's write, not the resolver's value"
    );
}
