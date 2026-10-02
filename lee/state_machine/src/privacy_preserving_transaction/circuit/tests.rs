#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    Identifier, Nullifier, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateWitness,
    SharedSecretKey, WitnessKind,
    account::{Account, AccountId, ActorState, Nonce},
    execution_state::{
        Boundary, BoundaryStep, DeliverySource, ExecutionError, PublicDelivery,
        PublicExecutionContext,
    },
    native_token::encode_balance,
    program::{Call, MessageEnvelope, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, PrivateAccountKind},
};
use test_guest_core::Script;

use super::*;
use crate::{
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{
            TWIN, TestPrivateKeys, credit, execution_error, init_pda_witness, init_witness,
            proving_input, root, scripted_id, scripted_programs, synthetic_program,
            test_private_account_keys_1, test_private_account_keys_2, transfer, update_pda_witness,
            update_witness,
        },
    },
};

const BOB: AccountId = AccountId::new([8; 32]);

fn regular_id(keys: &TestPrivateKeys, identifier: Identifier) -> AccountId {
    AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier)
}

// Proves `script` as the root turn of the `scripted` actor of the witness's account.
fn prove_scripted(
    witness: PrivateWitness,
    script: &Script,
    ciphertext_padding: Option<u32>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let root_actor = Actor::new(witness.account_id(), scripted_id());
    execute_and_prove(
        ProvingInput {
            private_witnesses: vec![witness],
            ciphertext_padding,
            ..proving_input(root(root_actor, script))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
}

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

    let sender = Actor::native_balance(sender_id);
    let root_transfer = transfer(recipient_account_id, balance_to_move);
    let (output, proof) = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![sender], [sender_id]),
            private_witnesses: vec![init_witness(&recipient_keys, Identifier::ZERO)],
            ..proving_input(root(sender, &root_transfer))
        },
        &Simulation {
            public_shards: [(sender, encode_balance(balance_to_move))].into(),
            ..Simulation::default()
        },
        &ProgramCatalog::default(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    // A native transfer runs no guest, so it claims no program image.
    assert!(output.program_image_claims.is_empty());

    assert_eq!(output.context.authorized_accounts, vec![sender_id]);
    // The journal carries the public call to settle and the delivery it assumes back, not a
    // claimed balance: the prover never read the sender's shard.
    assert_eq!(
        output.boundary,
        vec![
            BoundaryStep::CallPublic(PublicDelivery {
                envelope: MessageEnvelope {
                    source: DeliverySource::Root,
                    to: sender,
                    message: borsh::to_vec(&root_transfer).unwrap(),
                },
                grants: Vec::new(),
                pda_seeds: Vec::new(),
            }),
            BoundaryStep::EnterPrivate(credit(
                sender,
                Actor::native_balance(recipient_account_id),
                balance_to_move
            )),
            BoundaryStep::LeavePrivate,
            BoundaryStep::ReturnPublic,
        ]
    );
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
            ..proving_input(root(
                Actor::native_balance(sender_account_id),
                &transfer(recipient_account_id, balance_to_move),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.boundary, Boundary::default());
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
    let keys = test_private_account_keys_1();

    let (output, proof) = prove_scripted(
        init_witness(&keys, Identifier::ZERO),
        &Script::default(),
        None,
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
    let keys = test_private_account_keys_1();
    let identifier = Identifier::new([99; 32]);
    let account_id = regular_id(&keys, identifier);
    let account = Account::funded(1);
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    // A tag deliberately different from the address-derived one, so a passthrough is
    // distinguishable from re-derivation.
    let fed_tag = EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()).wrapping_add(1);

    let (output, proof) = prove_scripted(
        PrivateWitness {
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
        },
        &Script::default(),
        None,
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

    let keys = test_private_account_keys_1();
    let identifier = Identifier::new([7; 32]);
    let account_id = regular_id(&keys, identifier);
    let account = Account::default().with_shard(scripted_id(), ActorState::from(vec![9_u8; 200]));
    let expected_post_state = account.data.clone();
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let (padded, proof) = prove_scripted(
        PrivateWitness {
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
        },
        &Script::default(),
        Some(PAD),
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
    assert_eq!(post.data, expected_post_state);
}

#[test]
fn circuit_fails_when_turn_validity_windows_have_empty_intersection() {
    let account_keys = test_private_account_keys_1();
    let later = Script {
        block_window: (4..7).try_into().unwrap(),
        ..Script::default()
    };
    let earlier = Script {
        block_window: (1..4).try_into().unwrap(),
        ..Script::default()
    }
    .call(
        Actor::new(regular_id(&account_keys, Identifier::ZERO), scripted_id()),
        &later,
    );

    let result = prove_scripted(
        init_witness(&account_keys, Identifier::ZERO),
        &earlier,
        None,
    );

    assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
}

/// A private PDA bound with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_with_custom_identifier_encrypts_correct_kind() {
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier = Identifier::new([99; 32]);
    let account_id =
        AccountId::for_private_pda(&scripted_id(), &seed, &npk, &keys.vpk(), identifier);
    let init_nonce = Nonce::private_account_nonce_init(&account_id);
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let (output, _proof) = prove_scripted(
        init_pda_witness(&keys, identifier, (scripted_id(), seed)),
        &Script::default(),
        None,
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            account_id: scripted_id(),
            seed,
            identifier
        },
    );
}

// Spends `amount` from the private PDA, owned by `scripted` under its seed, into a public
// recipient: the PDA's `scripted` actor delegates its native actor by seed.
fn prove_pda_spend(
    handle_account: AccountId,
    witness: PrivateWitness,
    seed: PdaSeed,
    amount: u128,
) -> Result<PrivacyPreservingCircuitOutput, LeeError> {
    let recipient = Actor::native_balance(AccountId::new([0; 32]));
    execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![recipient], [recipient.account_id]),
            private_witnesses: vec![witness],
            ..proving_input(root(
                Actor::new(handle_account, scripted_id()),
                &Script::default().send(
                    Call::new(
                        Actor::native_balance(handle_account),
                        &transfer(recipient.account_id, amount),
                    )
                    .with_pda_seeds(vec![seed]),
                ),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .map(|(output, _proof)| output)
}

/// PDA withdraw: sends to the native token program to move balance from PDA to recipient.
/// Uses a default PDA (amount=0) because testing with a pre-funded PDA requires a
/// two-tx sequence with membership proofs.
#[test]
fn private_pda_withdraw() {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let pda_id = AccountId::for_private_pda(
        &scripted_id(),
        &seed,
        &keys.npk(),
        &keys.vpk(),
        Identifier::ZERO,
    );

    // amount=0: the PDA has no balance yet
    let output = prove_pda_spend(
        pda_id,
        init_pda_witness(&keys, Identifier::ZERO, (scripted_id(), seed)),
        seed,
        0,
    )
    .expect("PDA withdraw should succeed");

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
    let sender = Actor::native_balance(sender_id);

    let result = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![sender], [sender_id]),
            private_witnesses: vec![init_witness(&shared_keys, shared_identifier)],
            ..proving_input(root(sender, &transfer(shared_account_id, balance_to_move)))
        },
        &Simulation {
            public_shards: [(sender, encode_balance(balance_to_move))].into(),
            ..Simulation::default()
        },
        &ProgramCatalog::default(),
    );

    let (output, _proof) = result.expect("shared account receive should succeed");
    // Sender is public (no commitment), recipient is private (1 commitment)
    assert_eq!(output.private_actions.len(), 1);
}

/// A regular init with a non-default identifier, whether authorized by the held `ask` or foreign
/// (the caller does not own the account), produces a ciphertext that decrypts to
/// `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_authorized_and_foreign_inits_encrypt_regular_kind_with_identifier() {
    let keys = test_private_account_keys_1();
    let identifier = Identifier::new([99; 32]);
    let account_id = regular_id(&keys, identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&account_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    for (init, ask) in [("authorized", Some(keys.ask)), ("foreign", None)] {
        let witness = PrivateWitness {
            kind: WitnessKind::Regular { ask },
            ..init_witness(&keys, identifier)
        };
        let (output, _) = prove_scripted(witness, &Script::default(), None).unwrap();

        assert_eq!(
            decrypt_kind(&output, &ssk, 0),
            PrivateAccountKind::Regular(identifier),
            "{init} init"
        );
    }
}

/// A regular update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_authorized_update_encrypts_regular_kind_with_identifier() {
    let keys = test_private_account_keys_1();
    let identifier = Identifier::new([99; 32]);
    let account_id = regular_id(&keys, identifier);
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

    let (output, _) = prove_scripted(
        update_witness(
            &keys,
            identifier,
            account,
            commitment_set.get_proof_for(&commitment).unwrap(),
        ),
        &Script::default(),
        None,
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
    keys: &TestPrivateKeys,
    identifier: Identifier,
) -> (AccountId, Account, lee_core::MembershipProof) {
    let account_id = regular_id(keys, identifier);
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
    let keys = test_private_account_keys_1();
    let (_, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    prove_scripted(
        unauthorized_update(&keys, account, membership_proof),
        &Script::default(),
        None,
    )
    .unwrap();
}

fn unauthorized_update(
    keys: &TestPrivateKeys,
    account: Account,
    membership_proof: lee_core::MembershipProof,
) -> PrivateWitness {
    PrivateWitness {
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
    }
}

#[test]
fn a_signer_entry_does_not_authorize_a_private_witness_without_ask() {
    let keys = test_private_account_keys_1();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    let result = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(Vec::new(), [account_id]),
            private_witnesses: vec![unauthorized_update(&keys, account, membership_proof)],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &Script::default().authorized(),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

/// An `ask` that does not derive this account's `nsk` is not a credential for it.
#[test]
fn regular_update_with_wrong_ask_nsk_is_rejected() {
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    let result = prove_scripted(
        PrivateWitness {
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
        },
        &Script::default(),
        None,
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::InvalidAuthorizationKey { account_id: rejected } if rejected == account_id
    ));
}

/// An `ask` that does not derive this account's `npk` is not a credential for it.
#[test]
fn regular_init_with_non_chaining_ask_npk_is_rejected() {
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let account_id = regular_id(&keys, Identifier::ZERO);

    let result = prove_scripted(
        PrivateWitness {
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
        },
        &Script::default(),
        None,
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
    let keys = test_private_account_keys_1();
    let (_, account, membership_proof) = seeded_regular_account(&keys, Identifier::ZERO);

    let result = prove_scripted(
        unauthorized_update(&keys, account, membership_proof),
        &Script::default().authorized(),
        None,
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

/// Root private-PDA update attempt: `scripted` spends a PDA it owns via the native token
/// program.
fn pda_update_attempt(
    derivation_identifier: Identifier,
    witness_identifier: Identifier,
) -> Result<lee_core::PrivacyPreservingCircuitOutput, LeeError> {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let program_id = scripted_id();
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

    prove_pda_spend(
        pda_id,
        update_pda_witness(
            &keys,
            witness_identifier,
            (program_id, seed),
            pda_account,
            commitment_set.get_proof_for(&pda_commitment).unwrap(),
        ),
        seed,
        1,
    )
}

/// A private-PDA update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_update_encrypts_pda_kind_with_identifier() {
    let program_id = scripted_id();
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
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id = AccountId::for_private_pda(
        &scripted_id(),
        &seed,
        &npk,
        &keys.vpk(),
        Identifier::new([5; 32]),
    );

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(
                &keys,
                Identifier::new([99; 32]),
                (scripted_id(), seed),
            )],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &Script::default(),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::UndeclaredActor { actor } if actor.account_id == account_id
    ));
}

#[test]
fn a_signer_entry_does_not_authorize_a_private_pda() {
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier = Identifier::new([5; 32]);
    let account_id =
        AccountId::for_private_pda(&scripted_id(), &seed, &npk, &keys.vpk(), identifier);

    let result = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(Vec::new(), [account_id]),
            private_witnesses: vec![init_pda_witness(&keys, identifier, (scripted_id(), seed))],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &Script::default().authorized(),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let result = pda_update_attempt(Identifier::new([5; 32]), Identifier::new([99; 32]));

    assert!(matches!(
        execution_error(result),
        ExecutionError::UndeclaredActor { .. }
    ));
}

#[test]
fn the_prover_never_reads_a_public_shard() {
    let account_id = AccountId::new([7; 32]);
    let root_actor = Actor::new(account_id, scripted_id());
    let callee = Actor::new(account_id, TWIN);
    let script = Script::default().call(callee, &Script::write(vec![3; 16]));

    // `Prover` supplies no public shard, so executing either public turn would fail the proof.
    let (output, proof) = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![root_actor, callee], []),
            ..proving_input(root(root_actor, &script))
        },
        &Simulation::default(),
        &scripted_programs(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(
        output.boundary,
        vec![
            BoundaryStep::CallPublic(PublicDelivery {
                envelope: MessageEnvelope {
                    source: DeliverySource::Root,
                    to: root_actor,
                    message: borsh::to_vec(&script).unwrap(),
                },
                grants: Vec::new(),
                pda_seeds: Vec::new(),
            }),
            BoundaryStep::ReturnPublic,
        ]
    );
}

#[test]
fn a_send_to_an_actor_the_transaction_never_declared_is_rejected() {
    let keys = test_private_account_keys_1();
    let undeclared = Actor::native_balance(AccountId::new([8; 32]));

    let result = prove_scripted(
        init_witness(&keys, Identifier::ZERO),
        &Script::default().call(undeclared, &Script::default()),
        None,
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::UndeclaredActor { actor } if actor == undeclared
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

fn receive_receipt(program: &Program, input: &ReceiveInput) -> (Receipt, Response) {
    let receipt = prove_session(program, |env| Program::write_receive_input(input, env)).unwrap();
    let response = transition_journal(&receipt.journal.bytes).unwrap().response;
    (receipt, response)
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

// A circuit input whose root delivers `script` to the `program_account_id` actor of a fresh
// private account, with the supplied responses standing in for its turns.
fn direct_input(
    program_account_id: AccountId,
    script: &Script,
    claims: &[&Program],
    responses: Vec<Response>,
) -> PrivacyPreservingCircuitInput {
    let keys = test_private_account_keys_1();
    PrivacyPreservingCircuitInput {
        input: ProvingInput {
            root: root(
                Actor::new(regular_id(&keys, Identifier::ZERO), program_account_id),
                script,
            ),
            context: PublicExecutionContext::default(),
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
        },
        program_image_witnesses: claims_for(claims),
        shadow_program_witnesses: Vec::new(),
        responses,
        assumptions: Vec::new(),
    }
}

fn assert_circuit_rejects<T: std::fmt::Debug>(result: &Result<T, LeeError>, expected: &str) {
    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(msg)) if msg.contains(expected)),
        "expected the circuit to reject with {expected:?}, got {result:?}"
    );
}

// The root turn `direct_input` schedules for `script` on a `scripted` actor.
fn scripted_root_input(script: &Script, is_authorized: bool) -> ReceiveInput {
    let keys = test_private_account_keys_1();
    ReceiveInput {
        receiver: Actor::new(regular_id(&keys, Identifier::ZERO), scripted_id()),
        origin: None,
        is_authorized,
        pre_state: ActorState::empty(),
        message: borsh::to_vec(script).unwrap(),
    }
}

#[test]
fn a_hand_built_input_with_a_matching_receipt_proves() {
    let scripted = crate::test_methods::scripted();
    let (receipt, response) =
        receive_receipt(&scripted, &scripted_root_input(&Script::default(), true));
    let input = direct_input(
        scripted_id(),
        &Script::default(),
        &[&scripted],
        vec![response],
    );

    let output = prove_circuit_directly(&input, vec![receipt]).unwrap();

    assert_eq!(output.private_actions.len(), 1);
    assert_eq!(output.boundary, Boundary::default());
}

#[test]
fn a_guest_image_claim_for_the_reserved_id_is_refused() {
    let scripted = crate::test_methods::scripted();
    for reserved in [NATIVE_TOKEN_PROGRAM_ID, PROGRAM_LOADER_ACCOUNT_ID] {
        let (receipt, response) =
            receive_receipt(&scripted, &scripted_root_input(&Script::default(), true));
        let mut input = direct_input(
            scripted_id(),
            &Script::default(),
            &[&scripted],
            vec![response],
        );
        input
            .program_image_witnesses
            .push(ProgramImageWitness::Disclosed {
                account_id: reserved,
                image_id: scripted.id(),
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
    let input = direct_input(
        PROGRAM_LOADER_ACCOUNT_ID,
        &Script::default(),
        &[],
        Vec::new(),
    );

    let result = prove_circuit_directly(&input, Vec::new());

    assert_circuit_rejects(&result, "runs only in a wholly public execution");
}

#[test]
fn a_receipt_for_other_inputs_does_not_bind_in_the_circuit() {
    let scripted = crate::test_methods::scripted();
    // Proven against an unauthorized receiver, offered where the circuit schedules an authorized
    // one.
    let (receipt, response) =
        receive_receipt(&scripted, &scripted_root_input(&Script::default(), false));
    let input = direct_input(
        scripted_id(),
        &Script::default(),
        &[&scripted],
        vec![response],
    );

    let result = prove_circuit_directly(&input, vec![receipt]);

    assert_circuit_rejects(&result, "no receipt found to resolve assumption");
}

#[test]
fn an_undeclared_actor_is_rejected_by_the_circuit() {
    let scripted = crate::test_methods::scripted();
    let script = Script::default().call(Actor::native_balance(BOB), &Script::default());
    let (receipt, response) = receive_receipt(&scripted, &scripted_root_input(&script, true));
    let input = direct_input(scripted_id(), &script, &[&scripted], vec![response]);

    let result = prove_circuit_directly(&input, vec![receipt]);

    assert_circuit_rejects(
        &result,
        "which is neither a declared public actor nor private",
    );
}

#[test]
fn missing_responses_are_rejected_by_the_circuit() {
    let scripted = crate::test_methods::scripted();
    let input = direct_input(scripted_id(), &Script::default(), &[&scripted], Vec::new());

    let result = prove_circuit_directly(&input, Vec::new());

    assert_circuit_rejects(&result, "a scheduled turn must carry its response");
}

#[test]
fn surplus_responses_are_rejected_by_the_circuit() {
    let scripted = crate::test_methods::scripted();
    let (receipt, response) =
        receive_receipt(&scripted, &scripted_root_input(&Script::default(), true));
    let input = direct_input(
        scripted_id(),
        &Script::default(),
        &[&scripted],
        vec![response.clone(), response],
    );

    let result = prove_circuit_directly(&input, vec![receipt]);

    assert_circuit_rejects(
        &result,
        "A response was supplied for a turn nothing scheduled",
    );
}
