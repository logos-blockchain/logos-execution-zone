#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    Identifier, Nullifier, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateWitness,
    PublicAction, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, Nonce, ShardData},
    execution_state::{DeferredPublicEffect, ExecutionError},
    native_token::Instruction as NativeInstruction,
    program::{
        AccountMeta, ApplyInput, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, PlanInput, PrivateAccountKind,
    },
};

use super::*;
use crate::{
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{
            execution_error, init_pda_witness, init_witness, native_debit, synthetic_program,
            test_private_account_keys_1, test_private_account_keys_2, update_pda_witness,
            update_witness,
        },
    },
};

const ALICE: AccountId = AccountId::new([7; 32]);
const BOB: AccountId = AccountId::new([8; 32]);

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
fn prove_privacy_preserving_execution_circuit_public_and_private_accounts() {
    let recipient_keys = test_private_account_keys_1();
    let sender_id = AccountId::new([0; 32]);

    let recipient_account_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );

    let balance_to_move: u128 = 37;

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
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(recipient_account_id),
            ],
            signers: [sender_id].into(),
            private_witnesses: vec![init_witness(&recipient_keys, Identifier::ZERO)],
            instruction_data: Program::serialize_instruction(NativeInstruction::Transfer {
                amount: balance_to_move,
            })
            .unwrap(),
            ..Default::default()
        },
        &ProgramWithDependencies::native(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    // A native transfer runs no guest, so it claims no program image.
    assert!(output.program_image_claims.is_empty());

    let [action] = output.public_actions.try_into().unwrap();
    assert_eq!(action.account_id, sender_id);
    assert!(action.is_authorized);
    // The journal carries the effect to settle, not a claimed balance: the prover never read
    // the sender's shard, so it has nothing to assert about its contents.
    assert_eq!(action.effects, vec![native_debit(balance_to_move)]);
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
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();

    let sender_nonce = Nonce(0xdead_beef);
    let sender_account_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::ZERO,
    );
    let sender_pre_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let commitment_sender = Commitment::new(&sender_account_id, &sender_pre_account);

    let recipient_account_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );
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
                ProgramShardSelector::native_balance(sender_account_id),
                ProgramShardSelector::native_balance(recipient_account_id),
            ],
            private_witnesses: vec![
                update_witness(
                    &sender_keys,
                    Identifier::ZERO,
                    sender_pre_account,
                    commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                ),
                init_witness(&recipient_keys, Identifier::ZERO),
            ],
            instruction_data: Program::serialize_instruction(NativeInstruction::Transfer {
                amount: balance_to_move,
            })
            .unwrap(),
            ..Default::default()
        },
        &ProgramWithDependencies::native(),
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
    let identifier = Identifier::ZERO;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![init_witness(&keys, identifier)],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
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
    let identifier = Identifier::new([99; 32]);
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
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier,
                kind: WitnessKind::Regular {
                    ask: Some(keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: fed_tag,
                    nsk: keys.nsk(),
                    membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
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
fn note_ciphertext_is_padded_to_the_requested_length() {
    const PAD: u32 = 512;

    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier = Identifier::new([7; 32]);
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let program_account_id = AccountId::from_builtin_program(program.id());
    let account = Account::default().with_shard(
        program_account_id,
        ShardData::try_from(vec![9_u8; 200]).unwrap(),
    );
    let expected_post_data = account.data.clone();
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let (padded, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, program_account_id)],
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier,
                kind: WitnessKind::Regular {
                    ask: Some(keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()),
                    nsk: keys.nsk(),
                    membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ciphertext_padding: Some(PAD),
            ..Default::default()
        },
        &synthetic_program(program),
    )
    .unwrap();

    assert!(proof.is_valid_for(&padded));
    assert_eq!(padded.private_actions.len(), 1);
    let ciphertext = &padded.private_actions[0].encrypted_post_state.ciphertext;
    assert_eq!(
        ciphertext.as_bytes().len(),
        usize::try_from(PAD).expect("pad fits in usize")
    );

    let shared_secret = SharedSecretKey::decapsulate(
        &padded.private_actions[0].encrypted_post_state.epk,
        &keys.d,
        &keys.z,
    )
    .unwrap();
    let (kind, post) = EncryptionScheme::decrypt(
        ciphertext,
        &shared_secret,
        &padded.private_actions[0].nullifier,
    )
    .unwrap();
    assert_eq!(kind, PrivateAccountKind::Regular(identifier));
    assert_eq!(post.data, expected_post_data);
}

#[test]
fn circuit_fails_when_chained_validity_windows_have_empty_intersection() {
    let account_keys = test_private_account_keys_1();
    let account_id = AccountId::for_regular_private_account(
        &account_keys.npk(),
        &account_keys.vpk(),
        Identifier::ZERO,
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
        validity_window_chain_caller.clone(),
        AccountId::from_builtin_program(validity_window_chain_caller.id()),
        [(
            AccountId::from_builtin_program(validity_window.id()),
            validity_window,
        )]
        .into(),
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![init_witness(&account_keys, Identifier::ZERO)],
            instruction_data: instruction,
            ..Default::default()
        },
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
}

/// A private PDA bound with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_with_custom_identifier_encrypts_correct_kind() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier = Identifier::new([99; 32]);
    let account_id = AccountId::for_private_pda(
        &AccountId::from_builtin_program(program.id()),
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
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                identifier,
                (AccountId::from_builtin_program(program.id()), seed),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program.clone()),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            account_id: AccountId::from_builtin_program(program.id()),
            seed,
            identifier
        },
    );
}

/// PDA withdraw: chains to the native token program to move balance from PDA to recipient.
/// Uses a default PDA (amount=0) because testing with a pre-funded PDA requires a
/// two-tx sequence with membership proofs.
#[test]
fn private_pda_withdraw() {
    let program = crate::test_methods::pda_spend_proxy();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    // PDA (new, private PDA)
    let pda_id = AccountId::for_private_pda(
        &AccountId::from_builtin_program(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        Identifier::ZERO,
    );

    // Recipient (public)
    let recipient_id = AccountId::new([88; 32]);

    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        AccountId::from_builtin_program(program.id()),
        HashMap::new(),
    );

    // amount=0: the PDA has no balance yet
    let instruction = Program::serialize_instruction((seed, 0_u128)).unwrap();

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(pda_id),
                ProgramShardSelector::native_balance(recipient_id),
            ],
            signers: [recipient_id].into(),
            private_witnesses: vec![init_pda_witness(
                &keys,
                Identifier::ZERO,
                (AccountId::from_builtin_program(program.id()), seed),
            )],
            instruction_data: instruction,
            ..Default::default()
        },
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA withdraw should succeed");
    assert_eq!(output.private_actions.len(), 1);
}

/// Shared regular private account: receives funds via a native transfer directly,
/// no custom program needed. This demonstrates the non-PDA shared account flow where
/// keys are derived from GMS via `derive_keys_for_shared_account`. The shared account
/// uses the standard foreign private account path and works with auth-transfer's
/// transfer path like any other private account.
#[test]
fn shared_account_receives_via_simple_transfer() {
    let shared_keys = test_private_account_keys_1();
    let shared_npk = shared_keys.npk();
    let shared_identifier = Identifier::new([42; 32]);

    // Sender: public account with balance, owned by auth-transfer
    let sender_id = AccountId::new([99; 32]);

    // Recipient: shared private account (new, foreign)
    let shared_account_id = AccountId::from((&shared_npk, &shared_keys.vpk(), shared_identifier));

    let balance_to_move: u128 = 100;
    let instruction = Program::serialize_instruction(NativeInstruction::Transfer {
        amount: balance_to_move,
    })
    .unwrap();

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(shared_account_id),
            ],
            signers: [sender_id].into(),
            private_witnesses: vec![init_witness(&shared_keys, shared_identifier)],
            instruction_data: instruction,
            ..Default::default()
        },
        &ProgramWithDependencies::native(),
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
    let identifier = Identifier::new([99; 32]);
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&account_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let (output, _) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![init_witness(&keys, identifier)],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
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
    let identifier = Identifier::new([99; 32]);
    let recipient_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &recipient_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&recipient_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let (output, _) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(recipient_id)],
            private_witnesses: vec![init_witness(&keys, identifier)],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
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
    let identifier = Identifier::new([99; 32]);
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
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![update_witness(
                &keys,
                identifier,
                account,
                commitment_set.get_proof_for(&commitment).unwrap(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
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
    identifier: Identifier,
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
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: Identifier::ZERO,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    )
    .unwrap();
}

#[test]
fn a_signer_entry_does_not_authorize_a_private_witness_without_ask() {
    let program = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            signers: [account_id].into(),
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: Identifier::ZERO,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

/// An `ask` that does not derive this account's `nsk` is not a credential for it.
#[test]
fn regular_update_with_wrong_ask_nsk_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: Identifier::ZERO,
                kind: WitnessKind::Regular {
                    ask: Some(foreign.ask),
                },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::InvalidAuthorizationKey { account_id: rejected } if rejected == account_id
    ));
}

/// An `ask` that does not derive this account's `npk` is not a credential for it.
#[test]
fn regular_init_with_non_chaining_ask_npk_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let account_id =
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: Identifier::ZERO,
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
        &synthetic_program(program),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::InvalidAuthorizationKey { account_id: rejected } if rejected == account_id
    ));
}

/// A program that asserts authorization over its pre-states rejects a regular private account
/// whose witness supplied no `ask`.
#[test]
fn auth_asserting_program_rejects_unauthorized_regular_private_account() {
    let program = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: Identifier::ZERO,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof,
                },
            }],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

/// Root-call private-PDA update attempt: `pda_spend_proxy` spends a PDA it owns via the
/// native token program.
fn pda_update_attempt(
    derivation_identifier: Identifier,
    witness_identifier: Identifier,
) -> Result<lee_core::PrivacyPreservingCircuitOutput, LeeError> {
    let program = crate::test_methods::pda_spend_proxy();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let program_id = AccountId::from_builtin_program(program.id());
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

    let program_with_deps = ProgramWithDependencies::new(program, program_id, HashMap::new());

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(pda_id),
                ProgramShardSelector::native_balance(recipient_id),
            ],
            signers: [recipient_id].into(),
            private_witnesses: vec![update_pda_witness(
                &keys,
                witness_identifier,
                (program_id, seed),
                pda_account,
                commitment_set.get_proof_for(&pda_commitment).unwrap(),
            )],
            instruction_data: Program::serialize_instruction((seed, 1_u128)).unwrap(),
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
    let program_id = AccountId::from_builtin_program(crate::test_methods::pda_spend_proxy().id());
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let identifier = Identifier::new([99; 32]);

    let output = pda_update_attempt(identifier, identifier)
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
fn private_pda_init_identifier_mismatch_fails() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id = AccountId::for_private_pda(
        &AccountId::from_builtin_program(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        Identifier::new([5; 32]),
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                Identifier::new([99; 32]),
                (AccountId::from_builtin_program(program.id()), seed),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::WitnessNotInRoot { .. }
    ));
}

#[test]
fn a_signer_entry_does_not_authorize_a_private_pda() {
    let program = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier = Identifier::new([5; 32]);
    let account_id = AccountId::for_private_pda(
        &AccountId::from_builtin_program(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        identifier,
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::native_balance(account_id)],
            signers: [account_id].into(),
            private_witnesses: vec![init_pda_witness(
                &keys,
                identifier,
                (AccountId::from_builtin_program(program.id()), seed),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let result = pda_update_attempt(Identifier::new([5; 32]), Identifier::new([99; 32]));

    assert!(matches!(
        execution_error(result),
        ExecutionError::WitnessNotInRoot { .. }
    ));
}

fn forwarder_over_callee() -> (ProgramWithDependencies, AccountId, AccountId) {
    let forwarder = crate::test_methods::shard_forwarder();
    let callee = crate::test_methods::data_changer();
    let forwarder_id = AccountId::from_builtin_program(forwarder.id());
    let callee_id = AccountId::from_builtin_program(callee.id());

    (
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into()),
        forwarder_id,
        callee_id,
    )
}

fn forwarder_instruction(calls: &[(AccountId, ProgramShardSelector, Vec<u8>)]) -> Vec<u8> {
    Program::serialize_instruction(calls.to_vec()).unwrap()
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
    forwarder_instruction(&calls_at(
        account_id,
        &[(callee_id, data_changer_instruction(write))],
    ))
}

#[test]
fn the_prover_never_reads_a_public_shard() {
    let (program, forwarder_id, callee_id) = forwarder_over_callee();
    let account_id = AccountId::new([7; 32]);
    let write = vec![3; 16];

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, forwarder_id)],
            instruction_data: forward_to(account_id, callee_id, &write),
            ..Default::default()
        },
        &program,
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    let [action] = <[_; 1]>::try_from(output.public_actions).unwrap();
    assert_eq!(action.account_id, account_id);
    assert_eq!(
        action.effects,
        vec![DeferredPublicEffect {
            program_account_id: callee_id,
            shard_program_account_id: callee_id,
            data: borsh::to_vec(&write).unwrap(),
        }]
    );
}

#[test]
fn a_chained_call_on_an_account_the_root_never_named_is_rejected() {
    let forwarder = crate::test_methods::shard_forwarder();
    let echo = crate::test_methods::noop();
    let forwarder_id = AccountId::from_builtin_program(forwarder.id());
    let echo_id = AccountId::from_builtin_program(echo.id());
    let program = ProgramWithDependencies::new(forwarder, forwarder_id, [(echo_id, echo)].into());

    let account_id = AccountId::new([7; 32]);
    let fresh_id = AccountId::new([8; 32]);
    let instruction = forwarder_instruction(&[(
        echo_id,
        ProgramShardSelector::native_balance(fresh_id),
        Program::serialize_instruction(()).unwrap(),
    )]);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, forwarder_id)],
            instruction_data: instruction.clone(),
            ..Default::default()
        },
        &program,
    );
    assert!(matches!(
        execution_error(result),
        ExecutionError::UnknownAccount { account_id } if account_id == fresh_id
    ));

    let keys = test_private_account_keys_1();
    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, forwarder_id)],
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            instruction_data: instruction,
            ..Default::default()
        },
        &program,
    );
    assert!(matches!(
        execution_error(result),
        ExecutionError::WitnessNotInRoot { .. }
    ));
}

fn prove_circuit_directly(
    circuit_input: &PrivacyPreservingCircuitInput,
    receipts: Vec<Receipt>,
) -> Result<PrivacyPreservingCircuitOutput, LeeError> {
    let mut env_builder = ExecutorEnv::builder();
    for receipt in receipts {
        env_builder.add_assumption(receipt);
    }
    env_builder.write_slice(&to_frame(&borsh::to_vec(circuit_input)?));
    let prove_info = default_prover()
        .prove_with_opts(
            env_builder.build().unwrap(),
            PRIVACY_PRESERVING_CIRCUIT_ELF,
            &ProverOpts::succinct(),
        )
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;
    Ok(borsh::from_slice(from_frame(&prove_info.receipt.journal.bytes).unwrap()).unwrap())
}

fn plan_receipt(program: &Program, input: &PlanInput) -> (Receipt, ProvenCall) {
    let receipt = prove_session(program, |env| Program::write_plan_inputs(input, env)).unwrap();
    let plan = plan_journal(&receipt.journal.bytes).unwrap();
    (
        receipt,
        ProvenCall {
            plan,
            private_apply_outputs: Vec::new(),
        },
    )
}

fn apply_receipt(program: &Program, input: &ApplyInput) -> (Receipt, ApplyOutput) {
    let receipt = prove_session(program, |env| Program::write_apply_inputs(input, env)).unwrap();
    let output = apply_journal(&receipt.journal.bytes).unwrap();
    (receipt, output)
}

fn claims_for(programs: &[&Program]) -> Vec<ProgramImageWitness> {
    programs
        .iter()
        .map(|program| ProgramImageWitness::Disclosed {
            account_id: AccountId::from_builtin_program(program.id()),
            image_id: program.id(),
        })
        .collect()
}

fn direct_input(
    program: &Program,
    shard_selectors: Vec<ProgramShardSelector>,
    authorized_accounts: Vec<AccountId>,
    instruction: InstructionData,
    witnesses: Vec<PrivateWitness>,
    claims: &[&Program],
    calls: Vec<ProvenCall>,
) -> PrivacyPreservingCircuitInput {
    PrivacyPreservingCircuitInput {
        root: RootCall {
            program_account_id: AccountId::from_builtin_program(program.id()),
            shard_selectors,
            instruction_data: instruction,
            authorized_accounts,
        },
        private_witnesses: witnesses,
        dummy_inputs: Vec::new(),
        ciphertext_padding: None,
        program_image_witnesses: claims_for(claims),
        shadow_program_witnesses: Vec::new(),
        calls,
    }
}

fn assert_circuit_rejects<T: std::fmt::Debug>(result: &Result<T, LeeError>, expected: &str) {
    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(msg)) if msg.contains(expected)),
        "expected the circuit to reject with {expected:?}, got {result:?}"
    );
}

fn alice_input(program: &Program, is_authorized: bool) -> PlanInput {
    PlanInput {
        self_account_id: AccountId::from_builtin_program(program.id()),
        caller_account_id: None,
        accounts: vec![AccountMeta::native_balance(ALICE, is_authorized)],
        instruction_data: Program::serialize_instruction(()).unwrap(),
    }
}

#[test]
fn a_hand_built_input_with_a_matching_receipt_proves() {
    let noop = crate::test_methods::noop();
    let (receipt, call) = plan_receipt(&noop, &alice_input(&noop, true));
    let input = direct_input(
        &noop,
        vec![ProgramShardSelector::native_balance(ALICE)],
        vec![ALICE],
        Program::serialize_instruction(()).unwrap(),
        Vec::new(),
        &[&noop],
        vec![call],
    );

    let output = prove_circuit_directly(&input, vec![receipt]).unwrap();

    // A handle an accepted plan used contributes its row even though it produced no effect:
    // that is what binds the claimed authorization to something settlement re-checks.
    assert_eq!(
        output.public_actions,
        vec![PublicAction {
            account_id: ALICE,
            is_authorized: true,
            effects: Vec::new(),
        }]
    );
}

#[test]
fn a_guest_image_claim_for_the_reserved_id_is_refused() {
    let noop = crate::test_methods::noop();
    for reserved in [NATIVE_TOKEN_PROGRAM_ID, PROGRAM_LOADER_ACCOUNT_ID] {
        let (receipt, call) = plan_receipt(&noop, &alice_input(&noop, true));
        let mut input = direct_input(
            &noop,
            vec![ProgramShardSelector::native_balance(ALICE)],
            vec![ALICE],
            Program::serialize_instruction(()).unwrap(),
            Vec::new(),
            &[&noop],
            vec![call],
        );
        input
            .program_image_witnesses
            .push(ProgramImageWitness::Disclosed {
                account_id: reserved,
                image_id: noop.id(),
            });

        let result = prove_circuit_directly(&input, vec![receipt]);

        assert_circuit_rejects(
            &result,
            "A reserved program account has no deployable bytecode to claim",
        );
    }
}

#[test]
fn a_private_call_into_the_program_loader_is_refused() {
    let noop = crate::test_methods::noop();
    let mut input = direct_input(
        &noop,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &[],
        Vec::new(),
    );
    input.root.program_account_id = PROGRAM_LOADER_ACCOUNT_ID;

    let result = prove_circuit_directly(&input, Vec::new());

    assert_circuit_rejects(&result, "cannot be proven");
}

#[test]
fn a_receipt_for_other_inputs_does_not_bind_in_the_circuit() {
    let noop = crate::test_methods::noop();
    // Proven against an unauthorized handle, offered where the root claims ALICE signed.
    let (receipt, call) = plan_receipt(&noop, &alice_input(&noop, false));
    let input = direct_input(
        &noop,
        vec![ProgramShardSelector::native_balance(ALICE)],
        vec![ALICE],
        Program::serialize_instruction(()).unwrap(),
        Vec::new(),
        &[&noop],
        vec![call],
    );

    let result = prove_circuit_directly(&input, vec![receipt]);

    assert_circuit_rejects(&result, "plan echoed an input it was not given");
}

#[test]
fn forbidden_effects_are_rejected_by_the_circuit() {
    let writer = crate::test_methods::data_changer();
    let keys = test_private_account_keys_1();
    let witness = init_witness(&keys, Identifier::ZERO);
    let target = witness.account_id();
    let instruction = Program::serialize_instruction(vec![9_u8; 4]).unwrap();

    // The writer names the target's *native* shard, which it does not own.
    let plan_input = PlanInput {
        self_account_id: AccountId::from_builtin_program(writer.id()),
        caller_account_id: None,
        accounts: vec![AccountMeta::native_balance(target, true)],
        instruction_data: instruction.clone(),
    };
    let (plan_proof, mut call) = plan_receipt(&writer, &plan_input);
    let (apply_proof, output) = apply_receipt(
        &writer,
        &ApplyInput {
            self_account_id: AccountId::from_builtin_program(writer.id()),
            selector: ProgramShardSelector::native_balance(target),
            pre_data: ShardData::empty(),
            effect_data: call.plan.effects[0].data.clone(),
        },
    );
    call.private_apply_outputs = vec![output];

    let input = direct_input(
        &writer,
        vec![ProgramShardSelector::native_balance(target)],
        Vec::new(),
        instruction,
        vec![witness],
        &[&writer],
        vec![call],
    );

    let result = prove_circuit_directly(&input, vec![plan_proof, apply_proof]);

    assert_circuit_rejects(&result, "wrote data on a shard selector of");
}

#[test]
fn an_undeclared_child_account_is_rejected_by_the_circuit() {
    let forwarder = crate::test_methods::references_undeclared_account();
    let noop = crate::test_methods::noop();
    let instruction = Program::serialize_instruction((
        noop.id(),
        Program::serialize_instruction(()).unwrap(),
        BOB,
    ))
    .unwrap();
    let (root_receipt, root_call) = plan_receipt(
        &forwarder,
        &PlanInput {
            self_account_id: AccountId::from_builtin_program(forwarder.id()),
            caller_account_id: None,
            accounts: vec![AccountMeta::native_balance(ALICE, true)],
            instruction_data: instruction.clone(),
        },
    );
    let (child_receipt, child_call) = plan_receipt(
        &noop,
        &PlanInput {
            self_account_id: AccountId::from_builtin_program(noop.id()),
            caller_account_id: Some(AccountId::from_builtin_program(forwarder.id())),
            accounts: vec![AccountMeta::native_balance(BOB, false)],
            instruction_data: Program::serialize_instruction(()).unwrap(),
        },
    );
    let input = direct_input(
        &forwarder,
        vec![ProgramShardSelector::native_balance(ALICE)],
        vec![ALICE],
        instruction,
        Vec::new(),
        &[&forwarder, &noop],
        vec![root_call, child_call],
    );

    let result = prove_circuit_directly(&input, vec![root_receipt, child_receipt]);

    assert_circuit_rejects(&result, "not an input of the root call");
}

#[test]
fn missing_call_wrappers_are_rejected_by_the_circuit() {
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let noop = crate::test_methods::noop();
    let instruction = Program::serialize_instruction((
        noop.id(),
        Program::serialize_instruction(()).unwrap(),
        true,
        Vec::<PdaSeed>::new(),
    ))
    .unwrap();
    let (receipt, call) = plan_receipt(
        &forwarder,
        &PlanInput {
            self_account_id: AccountId::from_builtin_program(forwarder.id()),
            caller_account_id: None,
            accounts: vec![AccountMeta::native_balance(ALICE, true)],
            instruction_data: instruction.clone(),
        },
    );
    let input = direct_input(
        &forwarder,
        vec![ProgramShardSelector::native_balance(ALICE)],
        vec![ALICE],
        instruction,
        Vec::new(),
        &[&forwarder, &noop],
        vec![call],
    );

    let result = prove_circuit_directly(&input, vec![receipt]);

    assert_circuit_rejects(&result, "a scheduled call must carry its call transcript");
}

#[test]
fn surplus_call_wrappers_are_rejected_by_the_circuit() {
    let noop = crate::test_methods::noop();
    let (receipt, call) = plan_receipt(&noop, &alice_input(&noop, true));
    let input = direct_input(
        &noop,
        vec![ProgramShardSelector::native_balance(ALICE)],
        vec![ALICE],
        Program::serialize_instruction(()).unwrap(),
        Vec::new(),
        &[&noop],
        vec![call.clone(), call],
    );

    let result = prove_circuit_directly(&input, vec![receipt]);

    assert_circuit_rejects(&result, "a call nothing scheduled");
}

#[test]
fn a_private_effect_must_carry_exactly_its_own_apply_output() {
    let writer = crate::test_methods::data_changer();
    let writer_id = AccountId::from_builtin_program(writer.id());
    let keys = test_private_account_keys_1();
    let witness = init_witness(&keys, Identifier::ZERO);
    let target = witness.account_id();
    let written = vec![4_u8; 6];
    let instruction = Program::serialize_instruction(written).unwrap();

    let (plan_proof, call) = plan_receipt(
        &writer,
        &PlanInput {
            self_account_id: writer_id,
            caller_account_id: None,
            accounts: vec![AccountMeta::new(target, true, writer_id)],
            instruction_data: instruction.clone(),
        },
    );
    let (apply_proof, output) = apply_receipt(
        &writer,
        &ApplyInput {
            self_account_id: writer_id,
            selector: ProgramShardSelector::new(target, writer_id),
            pre_data: ShardData::empty(),
            effect_data: call.plan.effects[0].data.clone(),
        },
    );

    let build = |private_apply_outputs: Vec<ApplyOutput>| {
        direct_input(
            &writer,
            vec![ProgramShardSelector::new(target, writer_id)],
            Vec::new(),
            instruction.clone(),
            vec![init_witness(&keys, Identifier::ZERO)],
            &[&writer],
            vec![ProvenCall {
                plan: call.plan.clone(),
                private_apply_outputs,
            }],
        )
    };

    let missing = prove_circuit_directly(&build(Vec::new()), vec![plan_proof.clone()]);
    assert_circuit_rejects(&missing, "must carry its apply output");

    let surplus = prove_circuit_directly(
        &build(vec![output.clone(), output.clone()]),
        vec![plan_proof.clone(), apply_proof.clone()],
    );
    assert_circuit_rejects(&surplus, "more apply outputs than it emitted");

    let matched = prove_circuit_directly(&build(vec![output]), vec![plan_proof, apply_proof]);
    assert!(
        matched.is_ok(),
        "the matching transcript must prove: {matched:?}"
    );
}
