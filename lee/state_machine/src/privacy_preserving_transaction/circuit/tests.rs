#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    Nullifier, NullifierPublicKey, NullifierWitness, PrivacyPreservingCircuitOutput,
    PrivateWitness, PublicAction, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, BalanceDiff, Nonce, data::Data},
    program::{DeferReads, PdaSeed, PrivateAccountKind},
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

// Host-side mirror of `stripped_token`'s `Instruction`/`TokenAccountData`/`TokenDiff` — the
// guest crate isn't a host dependency, so these can't be imported directly, only match the
// borsh layout. `stripped_token_and_forward` reuses the same `TokenDiff`/`TokenAccountData`
// shapes for its own `Incremental` resolution (`Add` only).
#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    Initialize { balance: u128 },
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
enum TokenDiff {
    Add(u128),
}

// Host-side mirror of `stripped_token_and_forward`'s `ProbeAssertion` — `Real` wraps the real
// `lee_core::program::DeferReads`, a genuine host dependency, so no separate mirror is needed
// for it.
#[derive(borsh::BorshSerialize)]
enum ProbeAssertion {
    None,
    Real(DeferReads),
    Unrelated,
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

/// `Probe`'s cost stays within `PROBE_CYCLE_BUDGET` for every `Incremental`-capable test-method
/// guest — catches a guest's `Probe` arm doing real work, or the budget being tightened below
/// what a legitimate guest needs.
#[test]
fn probe_cycles_stay_within_budget_for_every_incremental_capable_test_method() {
    for (name, program) in [
        ("stripped_token", crate::test_methods::stripped_token()),
        (
            "stripped_token_and_forward",
            crate::test_methods::stripped_token_and_forward(),
        ),
    ] {
        let pre_state =
            AccountWithMetadata::new(Account::default(), false, AccountId::new([0; 32]));

        let mut env_builder = ExecutorEnv::builder();
        env_builder.write_slice(&lee_core::to_borsh_frame(
            &lee_core::program::CallKind::Incremental,
        ));
        let input = lee_core::program::ProgramInput {
            self_account_id: program.id().into(),
            caller_account_id: None,
            pre_states: vec![pre_state],
            instruction: borsh::to_vec(&IncrementalCall::Probe(Vec::new())).unwrap(),
        };
        env_builder.write_slice(&lee_core::to_frame(&borsh::to_vec(&input).unwrap()));

        let session_info = risc0_zkvm::default_executor()
            .execute(env_builder.build().unwrap(), program.elf())
            .unwrap_or_else(|e| panic!("{name}'s Probe response must execute cleanly: {e}"));

        assert!(
            session_info.cycles() <= PROBE_CYCLE_BUDGET,
            "{name}'s Probe response used {} cycles, expected at most PROBE_CYCLE_BUDGET \
             ({PROBE_CYCLE_BUDGET})",
            session_info.cycles()
        );
    }
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
            program_owner: program.id().into(),
            balance: 100,
            ..Account::default()
        },
        true,
        AccountId::new([0; 32]),
    );

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_account_id);

    let balance_to_move: u128 = 37;

    let expected_sender_post = Account {
        program_owner: program.id().into(),
        balance: 100 - balance_to_move,
        nonce: Nonce::default(),
        data: Data::default(),
    };

    let expected_recipient_post = Account {
        balance: balance_to_move,
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        ..Account::default()
    };

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
    let PublicAction::Bound { pre, post } = action else {
        panic!("simple_balance_transfer does not support Incremental: expected Bound");
    };
    assert_eq!(pre, expected_sender_pre);
    assert_eq!(post, expected_sender_post);
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
        Account {
            balance: 100,
            nonce: sender_nonce,
            program_owner: program.id().into(),
            data: Data::default(),
        },
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

    let expected_private_account_1 = Account {
        program_owner: program.id().into(),
        balance: 100 - balance_to_move,
        nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ..Default::default()
    };
    let expected_private_account_2 = Account {
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
    let account = Account {
        program_owner: program.id().into(),
        balance: 1,
        ..Account::default()
    };
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
fn note_ciphertext_is_padded_to_the_requested_length() {
    const PAD: u32 = 512;

    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 7;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account {
        program_owner: program.id().into(),
        data: Data::try_from(vec![9_u8; 200]).unwrap(),
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let sender = AccountWithMetadata::new(account.clone(), true, account_id);

    let (padded, proof) = execute_and_prove_with_padded_inputs(
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
                view_tag: EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()),
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
        })],
        vec![],
        Some(PAD),
        &program.into(),
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
    assert_eq!(
        post,
        Account {
            nonce: post.nonce,
            ..account
        }
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
        validity_window_chain_caller.clone(),
        validity_window_chain_caller.id().into(),
        [(validity_window.id().into(), validity_window)].into(),
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

/// `Bound`/`Deferred` is decided by the executing program's own `Probe` claim, never declared
/// upfront by the caller. `stripped_token` unconditionally asserts `DeferReads::All`, so a public
/// account it touches comes out `Deferred`, carrying the raw delta for the sequencer to replay.
#[test]
fn public_account_touched_by_an_incremental_capable_program_is_deferred() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 100;

    let (output, proof) = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    )
    .expect("an Incremental-eligible public touch must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!("stripped_token supports Incremental: expected Deferred");
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, program_id);
    assert_eq!(resolution.caller_account_id, None);
    assert_eq!(resolution.post_balance_diff, BalanceDiff::Add(0));
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap().as_slice()
    );
}

/// A program that never implements `Incremental` and never even writes to an account — merely
/// reads it to decide what to do next — must still force that account `Bound`: its decision is
/// baked into the proof and never re-verified for a `Deferred` account. `acquire_and_forward`
/// echoes the account untouched and chains into `stripped_token`'s `Initialize`, which alone
/// would be `Deferred`-eligible.
#[test]
fn a_read_only_touch_by_a_non_incremental_program_forces_bound() {
    let forwarder = crate::test_methods::acquire_and_forward();
    let forwarder_id: AccountId = forwarder.id().into();
    let token = crate::test_methods::stripped_token();
    let token_program_id = token.id();
    let token_account_id: AccountId = token_program_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 55;

    let program_with_deps =
        ProgramWithDependencies::new(forwarder, forwarder_id, [(token_account_id, token)].into());

    let instruction = Program::serialize_instruction((
        Option::<Vec<u8>>::None,
        token_program_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a read-only touch by a non-Incremental program must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!(
            "acquire_and_forward doesn't implement Incremental: expected Bound, even though it \
             never wrote to the account"
        );
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token's Incremental resolution must still have run");
    assert_eq!(data.balance, balance);
}

/// A program that genuinely implements `Incremental` can still make a robinhood-style,
/// unverified decision by merely *reading* an account without asserting `DeferReads` — the
/// conservative default still forces `Bound` in that case. `stripped_token_and_forward` reads
/// account X (collapses to `unchanged`, no write), does not assert `DeferReads`, then chains
/// into `stripped_token`'s genuinely `Incremental`-eligible write on the same account. X must
/// still end up `Bound`.
#[test]
fn a_read_without_defer_reads_forces_bound_even_when_chained_into_a_genuine_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let token = crate::test_methods::stripped_token();
    let token_program_id = token.id();
    let token_account_id: AccountId = token_program_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps =
        ProgramWithDependencies::new(program, program_account_id, [(token_account_id, token)].into());

    // Byte-identical to a fresh account's `data` (empty) — collapses to an `unchanged` diff
    // (`post_data: None`), i.e. a genuine read of `account_id`, not a write. `ProbeAssertion::None`
    // is the point of this test.
    let instruction = Program::serialize_instruction((
        Vec::<u8>::new(),
        token_account_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        ProbeAssertion::None,
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a read chained into a different program's genuine write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!(
            "stripped_token_and_forward did not assert DeferReads: expected Bound, even though \
             stripped_token's write is genuinely Incremental-eligible"
        );
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token's Incremental resolution must still have run");
    assert_eq!(data.balance, balance);
}

/// The step-2 relaxation: same shape as the test above, except `stripped_token_and_forward`
/// asserts `DeferReads::All` this time. X's read is then treated as a no-op for classification,
/// and `stripped_token`'s genuine write is left `Deferred`, not forced `Bound`.
#[test]
fn a_read_with_defer_reads_all_stays_deferred_when_chained_into_a_genuine_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let token = crate::test_methods::stripped_token();
    let token_program_id = token.id();
    let token_account_id: AccountId = token_program_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps =
        ProgramWithDependencies::new(program, program_account_id, [(token_account_id, token)].into());

    let instruction = Program::serialize_instruction((
        Vec::<u8>::new(),
        token_account_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        ProbeAssertion::Real(DeferReads::All),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("an asserted-safe read chained into a genuine write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!(
            "stripped_token_and_forward asserted DeferReads::All: expected Deferred, not \
             Bound-forced by its own read"
        );
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, token_program_id.into());
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap().as_slice()
    );
}

/// `DeferReads::ReadOnly` covers reads, not writes. `stripped_token_and_forward`'s own touch on
/// X is a read (it collapses to `unchanged`), so `ReadOnly` covers it — X's read is a no-op for
/// classification, and `stripped_token`'s genuine, separately-called write is left `Deferred`.
#[test]
fn a_read_with_defer_reads_read_only_stays_deferred_when_chained_into_a_genuine_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let token = crate::test_methods::stripped_token();
    let token_program_id = token.id();
    let token_account_id: AccountId = token_program_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps =
        ProgramWithDependencies::new(program, program_account_id, [(token_account_id, token)].into());

    let instruction = Program::serialize_instruction((
        Vec::<u8>::new(),
        token_account_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        ProbeAssertion::Real(DeferReads::ReadOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a ReadOnly-asserted read chained into a genuine write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!(
            "stripped_token_and_forward's own touch on X is a read, which ReadOnly covers: expected Deferred"
        );
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, token_program_id.into());
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap().as_slice()
    );
}

/// The inverse: `DeferReads::WriteOnly` does not cover reads. `stripped_token_and_forward`'s own
/// touch on X is a read, so `WriteOnly` doesn't cover it — X is forced `Bound`, even though
/// `stripped_token`'s separately-called write on the same account would itself have been
/// `Deferred`-eligible.
#[test]
fn a_read_with_defer_reads_write_only_forces_bound_even_when_chained_into_a_genuine_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let token = crate::test_methods::stripped_token();
    let token_program_id = token.id();
    let token_account_id: AccountId = token_program_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps =
        ProgramWithDependencies::new(program, program_account_id, [(token_account_id, token)].into());

    let instruction = Program::serialize_instruction((
        Vec::<u8>::new(),
        token_account_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        ProbeAssertion::Real(DeferReads::WriteOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a WriteOnly-asserted read chained into a genuine write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!(
            "stripped_token_and_forward's own touch on X is a read, which WriteOnly doesn't cover: expected Bound"
        );
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token's Incremental resolution must still have run");
    assert_eq!(data.balance, balance);
}

/// `DeferReads::WriteOnly` covers a genuine write by the asserting program itself — no chaining
/// into a different program needed, since the program whose `Probe` claim is being checked is
/// the same one writing X. `stripped_token_and_forward` writes X directly (its own `Incremental`
/// resolves `TokenDiff::Add` too), then is forced onward (it always forwards) to
/// `defer_asserting_noop`, which only reads X and unconditionally asserts `DeferReads::All` on
/// its own `Probe`, so it never disturbs this classification.
#[test]
fn a_write_only_claim_defers_a_genuine_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let terminator = crate::test_methods::defer_asserting_noop();
    let terminator_id = terminator.id();
    let terminator_account_id: AccountId = terminator_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_account_id,
        [(terminator_account_id, terminator)].into(),
    );

    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap(),
        terminator_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::Real(DeferReads::WriteOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a WriteOnly-asserted genuine write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!("stripped_token_and_forward asserted WriteOnly on its own write: expected Deferred");
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, program_account_id);
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap().as_slice()
    );
}

/// The inverse of the test above: `DeferReads::ReadOnly` does not cover writes, so even a
/// genuine write by the asserting program itself is forced `Bound`.
#[test]
fn a_read_only_claim_forces_bound_on_a_genuine_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let terminator = crate::test_methods::defer_asserting_noop();
    let terminator_id = terminator.id();
    let terminator_account_id: AccountId = terminator_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_account_id,
        [(terminator_account_id, terminator)].into(),
    );

    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap(),
        terminator_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::Real(DeferReads::ReadOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a ReadOnly-asserted write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!("stripped_token_and_forward asserted ReadOnly on a write: expected Bound");
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token_and_forward's own Incremental resolution must still have run");
    assert_eq!(data.balance, balance);
}

/// The behavioral change this redesign introduces: previously a genuine write was
/// unconditionally `Deferred`-eligible whenever the program implemented `Incremental`, with no
/// `Probe` claim needed at all. Now every touch — write or read — needs `Probe`'s claim to cover
/// it; asserting nothing forces `Bound`, even for a write the program's own `Incremental` logic
/// can resolve perfectly well.
#[test]
fn a_write_with_no_probe_claim_forces_bound() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let terminator = crate::test_methods::defer_asserting_noop();
    let terminator_id = terminator.id();
    let terminator_account_id: AccountId = terminator_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_account_id,
        [(terminator_account_id, terminator)].into(),
    );

    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap(),
        terminator_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::None,
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("an unclaimed write must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!("stripped_token_and_forward asserted no DeferReads claim: expected Bound");
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token_and_forward's own Incremental resolution must still have run");
    assert_eq!(data.balance, balance);
}

// The two tests below reuse the self-write-then-read shape from the tests above, but with two
// touches in the same run: `stripped_token_and_forward` (1) writes X itself, then (2) chains
// into itself again, echoing X's now-current data verbatim, so this second diff collapses to a
// no-op read and triggers a *second*, independent `Probe` call on the same program. (3) it's
// then forced onward once more (it always forwards) to `defer_asserting_noop`, which - unlike
// plain `noop` - is `Incremental`-aware and asserts `DeferReads::All`, so it never disturbs what
// (1) and (2) already decided. This shows a claim is evaluated per call, not per program: the
// same program, asked twice in the same run, can get two different answers to `covers()` because
// the touch kind differs between calls, even when it asserts the identical claim both times.

/// `WriteOnly` covers touch (1) (a write), so it's `Deferred`-eligible - but touch (2) (a read,
/// a *different* call) asserts the same claim and gets a different answer: `WriteOnly` doesn't
/// cover a read, so it forces `Bound`, discarding touch (1)'s pending resolution.
#[test]
fn a_write_only_claim_does_not_cover_a_later_read_in_a_different_call() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let terminator = crate::test_methods::defer_asserting_noop();
    let terminator_id = terminator.id();
    let terminator_account_id: AccountId = terminator_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_account_id,
        [
            (
                program_account_id,
                crate::test_methods::stripped_token_and_forward(),
            ),
            (terminator_account_id, terminator),
        ]
        .into(),
    );

    // Touch 2 (self-chained): echoes X's post-touch-1 data verbatim, so its diff collapses to
    // `post_data: None` and triggers a second, independent `Probe` on
    // `stripped_token_and_forward`.
    let touch2_instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenAccountData { balance: 1 }).unwrap(),
        terminator_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::Real(DeferReads::WriteOnly),
    ))
    .unwrap();

    // Touch 1 (top-level): a genuine `TokenDiff::Add(1)` on a fresh account, `WriteOnly`-covered.
    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(1)).unwrap(),
        program_account_id,
        touch2_instruction,
        ProbeAssertion::Real(DeferReads::WriteOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a WriteOnly-covered write followed by a WriteOnly-uncovered read must prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!(
            "touch (2) is a read, which WriteOnly doesn't cover: expected Bound, touch (1)'s Deferred entry discarded"
        );
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("touch (1)'s Incremental resolution must still be reflected");
    assert_eq!(data.balance, 1);
    assert_eq!(post.program_owner, program_account_id);
}

/// The other direction: `ReadOnly` doesn't cover touch (1) (a write), so X is forced `Bound`
/// immediately - before touch (2) (a read, covered by the same `ReadOnly` claim) ever runs.
/// Once `Bound`, `Bound` stays: touch (2)'s coverage can't retroactively rescue it back to
/// `Deferred`.
#[test]
fn a_read_only_claim_cannot_rescue_an_earlier_uncovered_write() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let terminator = crate::test_methods::defer_asserting_noop();
    let terminator_id = terminator.id();
    let terminator_account_id: AccountId = terminator_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_account_id,
        [
            (
                program_account_id,
                crate::test_methods::stripped_token_and_forward(),
            ),
            (terminator_account_id, terminator),
        ]
        .into(),
    );

    let touch2_instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenAccountData { balance: 1 }).unwrap(),
        terminator_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::Real(DeferReads::ReadOnly),
    ))
    .unwrap();

    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(1)).unwrap(),
        program_account_id,
        touch2_instruction,
        ProbeAssertion::Real(DeferReads::ReadOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a ReadOnly-uncovered write followed by a ReadOnly-covered read must prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!("touch (1) is a write, which ReadOnly doesn't cover: expected Bound");
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("touch (1)'s Incremental resolution must still be reflected");
    assert_eq!(data.balance, 1);
    assert_eq!(post.program_owner, program_account_id);
}

/// An unrelated event on `Probe`'s response must not be mistaken for `DeferReads`: the account
/// still forces `Bound`, proving the check matches the specific selector, not just "some event
/// was emitted".
#[test]
fn an_unrelated_probe_event_is_not_mistaken_for_defer_reads() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let token = crate::test_methods::stripped_token();
    let token_program_id = token.id();
    let token_account_id: AccountId = token_program_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let balance: u128 = 42;

    let program_with_deps =
        ProgramWithDependencies::new(program, program_account_id, [(token_account_id, token)].into());

    let instruction = Program::serialize_instruction((
        Vec::<u8>::new(),
        token_account_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        ProbeAssertion::Unrelated,
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("an unrelated Probe event must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!(
            "stripped_token_and_forward asserted an unrelated event, not DeferReads: expected \
             Bound"
        );
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token's Incremental resolution must still have run");
    assert_eq!(data.balance, balance);
}

/// Once `Bound`, an account stays `Bound` permanently — a later `Incremental`-eligible touch
/// resolves immediately instead of re-entering `deferred`.
///
/// Ownership rules forbid a *different* program from writing an already-owned account, so the
/// only way to reach this is the same program touching it twice. `stripped_token_and_forward`
/// chains into itself: the first touch asserts no `DeferReads` claim at all, forcing `Bound`
/// regardless of whether it's resolvable (it isn't here either — a bare `TokenAccountData`
/// encoding, not a valid `TokenDiff`, so `Update` also declines); the second is a genuine
/// `TokenDiff::Add`, technically `Incremental`-resolvable but too late to defer — `Bound` is
/// permanent.
#[test]
fn a_later_incremental_touch_on_an_already_bound_account_resolves_without_deferring() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id = program.id();
    let program_account_id: AccountId = program_id.into();
    let noop = crate::test_methods::noop();
    let noop_id = noop.id();
    let noop_account_id: AccountId = noop_id.into();
    let account_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata::new(Account::default(), false, account_id);

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_account_id,
        [
            (program_account_id, crate::test_methods::stripped_token_and_forward()),
            (noop_account_id, noop),
        ]
        .into(),
    );

    let seed_balance: u128 = 7;
    let amount: u128 = 50;

    // Second touch: a genuine `TokenDiff::Add`, forwarding to `noop` to terminate the chain
    // (this program always forwards, so there's no way to skip a callee entirely).
    let second_touch_instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(amount)).unwrap(),
        noop_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::None,
    ))
    .unwrap();

    // First touch (top-level): a bare `TokenAccountData` encoding — not a valid `TokenDiff`, so
    // it's declined as `Unsupported` and forces `Bound` — then chains into itself for the second
    // touch above.
    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenAccountData {
            balance: seed_balance,
        })
        .unwrap(),
        program_account_id,
        second_touch_instruction,
        ProbeAssertion::None,
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a later Incremental-eligible touch on an already-Bound account must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!("the first touch is declined as Unsupported: expected Bound");
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("the second touch's Incremental resolution must still have run");
    assert_eq!(data.balance, seed_balance + amount);
}

/// The inverse: a pending `Deferred` resolution folds permanently into `Bound` the moment a
/// later touch forces it — the resolution is discarded (already reflected internally; only the
/// *emission* differs). `stripped_token_and_forward` asserts `WriteOnly` to make its own genuine
/// write `Deferred`-eligible; that write adds zero, so it never acquires ownership, leaving the
/// account free for `acquire_and_forward` — which doesn't implement `Incremental` at all, so its
/// `Probe` declines and it forces `Bound` — to acquire when it overwrites the data.
#[test]
fn a_bound_forcing_touch_discards_a_previously_deferred_accounts_pending_resolution() {
    let program = crate::test_methods::stripped_token_and_forward();
    let program_id: AccountId = program.id().into();
    let forwarder = crate::test_methods::acquire_and_forward();
    let forwarder_id = forwarder.id();
    let forwarder_account_id: AccountId = forwarder_id.into();
    let noop = crate::test_methods::noop();
    let noop_id = noop.id();
    let noop_account_id: AccountId = noop_id.into();

    let account_id = AccountId::new([1; 32]);
    let existing_balance: u128 = 100;
    let pre_account = Account {
        data: borsh::to_vec(&TokenAccountData {
            balance: existing_balance,
        })
        .unwrap()
        .try_into()
        .unwrap(),
        ..Account::default()
    };
    let pre = AccountWithMetadata::new(pre_account, false, account_id);
    let overwritten_data = vec![7_u8, 8, 9];

    let program_with_deps = ProgramWithDependencies::new(
        program,
        program_id,
        [(forwarder_account_id, forwarder), (noop_account_id, noop)].into(),
    );

    let forwarder_instruction = Program::serialize_instruction((
        Some(overwritten_data.clone()),
        noop_id,
        Program::serialize_instruction(()).unwrap(),
    ))
    .unwrap();

    // Add(0) adds nothing, so the Incremental-resolved data comes back byte-identical to
    // `existing_balance` — see the doc comment above for why that matters.
    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(0)).unwrap(),
        forwarder_account_id,
        forwarder_instruction,
        ProbeAssertion::Real(DeferReads::WriteOnly),
    ))
    .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .expect("a fold-in must still prove");

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!(
            "acquire_and_forward's later write forces Bound: expected Bound, deferred discarded"
        );
    };
    assert_eq!(post.data.as_ref(), overwritten_data.as_slice());
    assert_eq!(post.program_owner, forwarder_account_id);
}

/// A private account also gets genuinely resolved via `CallKind::Incremental` in-circuit, not
/// just the `UnsupportedCallKind` fallback. `stripped_token`'s `Initialize` emits an opaque
/// `TokenDiff` delta; if the circuit used it verbatim instead of running `Incremental`, decoding
/// the result as `TokenAccountData` here would fail outright.
#[test]
fn stripped_token_initialize_resolves_incremental_for_a_private_account() {
    let program = crate::test_methods::stripped_token();
    let keys = test_private_account_keys_1();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);
    let balance: u128 = 100;

    let init_nonce = Nonce::private_account_nonce_init(&account_id);
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let (output, proof) = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
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
    .expect("a private Incremental resolution must prove");

    assert!(proof.is_valid_for(&output));
    assert!(output.public_actions.is_empty());
    assert_eq!(output.private_actions.len(), 1);

    let (_kind, post_account) = EncryptionScheme::decrypt(
        &output.private_actions[0].encrypted_post_state.ciphertext,
        &shared_secret,
        &output.private_actions[0].nullifier,
    )
    .unwrap();

    let data: TokenAccountData = borsh::from_slice(post_account.data.as_ref()).expect(
        "decrypted data must decode as TokenAccountData: did Incremental resolution run?",
    );
    assert_eq!(data.balance, balance);
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

    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let (output, _proof) = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Pda {
                binding: Some((program.id().into(), seed)),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
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
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

    let auth_id: AccountId = simple_transfer.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(auth_id, simple_transfer)].into(),
    );

    // is_withdraw=false triggers init path (1 pre-state)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, false)).unwrap();

    let result = execute_and_prove(
        vec![pda_pre],
        instruction,
        vec![init_pda_witness(&keys, 0, None)],
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
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

    // Recipient (public)
    let recipient_id = AccountId::new([88; 32]);
    let recipient_pre = AccountWithMetadata::new(
        Account {
            program_owner: simple_transfer.id().into(),
            balance: 10000,
            ..Account::default()
        },
        true,
        recipient_id,
    );

    let auth_id: AccountId = simple_transfer.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(auth_id, simple_transfer)].into(),
    );

    // is_withdraw=true, amount=0 (PDA has no balance yet)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, true)).unwrap();

    let result = execute_and_prove(
        vec![pda_pre, recipient_pre],
        instruction,
        vec![
            init_pda_witness(&keys, 0, None),
            InputAccountIdentity::Public,
        ],
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
    let sender = AccountWithMetadata::new(
        Account {
            program_owner: program.id().into(),
            balance: 1000,
            ..Account::default()
        },
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
    let account = Account {
        program_owner: program.id().into(),
        balance: 1,
        ..Account::default()
    };
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

/// Builds an on-chain regular private account owned by `program`, returning its id, pre-state
/// and a membership proof for its commitment.
fn seeded_regular_account(
    keys: &crate::state::tests::TestPrivateKeys,
    program: &Program,
    identifier: u128,
) -> (AccountId, AccountWithMetadata, lee_core::MembershipProof) {
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account {
        program_owner: program.id().into(),
        balance: 1,
        ..Account::default()
    };
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
    let pda_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &keys.npk(),
        &keys.vpk(),
        derivation_identifier,
    );
    let pda_account = Account {
        program_owner: simple_transfer_id,
        balance: 1,
        ..Account::default()
    };
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let pda_pre = AccountWithMetadata::new(pda_account, declare_authorized, pda_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, AccountId::new([0; 32]));

    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(simple_transfer_id, simple_transfer)].into(),
    );

    execute_and_prove(
        vec![pda_pre, recipient_pre],
        Program::serialize_instruction((seed, 1_u128, simple_transfer_id)).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: witness_identifier,
                kind: WitnessKind::Pda { binding: None },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof: commitment_set.get_proof_for(&pda_commitment).unwrap(),
                },
            }),
            InputAccountIdentity::Public,
        ],
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
    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![init_pda_witness(
            &keys,
            99,
            Some((program.id().into(), seed)),
        )],
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
    let pre_state = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Pda {
                binding: Some((program.id().into(), seed)),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let result = pda_update_attempt(false, 5, 99);

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}
