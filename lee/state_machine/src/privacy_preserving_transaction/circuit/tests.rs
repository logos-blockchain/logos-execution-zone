#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use std::collections::BTreeSet;

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, EphemeralSecretKey, Nullifier,
    NullifierWitness, PrivacyPreservingCircuitOutput, PrivateWitness, ProgramImageClaim,
    RegularKey, RootCall, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, ActorState, Nonce},
    execution_state::{
        Boundary, BoundaryStep, ExecutionError, PublicExecutionContext, TransactionEntry,
    },
    native_token::encode_balance,
    program::{Call, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, PrivateAccountKind},
};
use test_guest_core::Script;

use super::*;
use crate::{
    V03State,
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{
            TWIN, TestPrivateKeys, credit, execution_error, init_pda_witness, init_witness,
            no_seal, proving_input, public_tx, root, scripted_id, scripted_programs, self_sends,
            synthetic_program, test_private_account_keys_1, test_private_account_keys_2, transfer,
            update_witness,
        },
    },
    validated_state_diff::ValidatedStateDiff,
};

const BOB: AccountId = AccountId::new([8; 32]);

// Proves `script` as the root transition of the `scripted` actor of the witness's account.
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
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
}

fn decrypt_kind(
    output: &PrivacyPreservingCircuitOutput,
    ssk: &SharedSecretKey,
    idx: usize,
) -> PrivateAccountKind {
    let (kind, _) = EncryptionScheme::decrypt(
        &output.execution.private_actions[idx]
            .encrypted_post_state
            .ciphertext,
        ssk,
        &output.execution.private_actions[idx].nullifier,
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

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk());

    let balance_to_move: u128 = 37;

    let expected_recipient_post = Account {
        nonce: Nonce::default().private_account_nonce_increment(&recipient_keys.nsk()),
        ..Account::funded(balance_to_move)
    };

    let init_nonce = Nonce::default().private_account_nonce_increment(&recipient_keys.nsk());
    let esk = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk).0;

    let sender = Actor::native_balance(sender_id);
    let root_transfer = transfer(recipient_account_id, balance_to_move);
    let (output, proof) = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![sender], [sender_id]),
            private_witnesses: vec![init_witness(&recipient_keys)],
            ..proving_input(root(sender, &root_transfer))
        },
        &Simulation {
            public_actor_states: [(sender, encode_balance(balance_to_move))].into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| true,
        no_seal,
    )
    .unwrap();

    assert!(proof.is_valid_for(&output.context, &output.execution));
    // A native transfer runs no guest, so it claims no program image.
    assert!(output.execution.program_image_claims.is_empty());

    assert_eq!(
        output.context.authorized_accounts,
        BTreeSet::from([sender_id])
    );
    // The journal carries the public root to settle and the delivery it assumes back, not a
    // claimed balance: the prover never read the sender's actor state.
    assert_eq!(
        output.execution.public_root,
        Some(RootCall {
            to: sender,
            message: borsh::to_vec(&root_transfer).unwrap(),
        })
    );
    assert_eq!(
        output.execution.boundary,
        vec![
            BoundaryStep::PublicToPrivate(credit(
                sender,
                Actor::native_balance(recipient_account_id),
                balance_to_move
            )),
            BoundaryStep::EndPrivateSubtree,
        ]
    );
    assert_eq!(output.execution.private_actions.len(), 1);

    let (_kind, recipient_post) = EncryptionScheme::decrypt(
        &output.execution.private_actions[0]
            .encrypted_post_state
            .ciphertext,
        &shared_secret,
        &output.execution.private_actions[0].nullifier,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_recipient_post);
}

#[test]
fn prove_privacy_preserving_execution_circuit_fully_private() {
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();

    let sender_nonce = Nonce(0xdead_beef);
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk());
    let sender_pre_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let commitment_sender = Commitment::new(&sender_account_id, &sender_pre_account);

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk());
    let balance_to_move: u128 = 37;

    let mut commitment_set = CommitmentSet::with_capacity(2);
    commitment_set.extend(std::slice::from_ref(&commitment_sender));
    let expected_new_nullifiers = vec![
        (
            Nullifier::for_account_update(&commitment_sender, &sender_keys.nsk()),
            commitment_set.digest(),
        ),
        (
            Nullifier::for_account_initialization(&recipient_account_id, &recipient_keys.nsk()),
            DUMMY_COMMITMENT_HASH,
        ),
    ];

    let expected_private_account_1 = Account {
        nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ..Account::funded(100 - balance_to_move)
    };
    let expected_private_account_2 = Account {
        nonce: Nonce::default().private_account_nonce_increment(&recipient_keys.nsk()),
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

    let init_nonce_2 = Nonce::default().private_account_nonce_increment(&recipient_keys.nsk());
    let esk_2 = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce_2);
    let shared_secret_2 =
        SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk_2).0;

    let (output, proof) = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![
                update_witness(
                    &sender_keys,
                    sender_pre_account,
                    commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                ),
                init_witness(&recipient_keys),
            ],
            ..proving_input(root(
                Actor::native_balance(sender_account_id),
                &transfer(recipient_account_id, balance_to_move),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| true,
        no_seal,
    )
    .unwrap();

    assert!(proof.is_valid_for(&output.context, &output.execution));
    assert_eq!(output.execution.boundary, Boundary::default());
    let sender_nullifier = expected_new_nullifiers[0].0;
    let recipient_nullifier = expected_new_nullifiers[1].0;

    let mut sorted_commitments = expected_new_commitments;
    sorted_commitments.sort_unstable_by_key(Commitment::to_byte_array);
    assert_eq!(output.execution.commitments(), sorted_commitments);

    let mut sorted_nullifiers = expected_new_nullifiers;
    sorted_nullifiers.sort_unstable_by_key(|(nullifier, _)| nullifier.to_byte_array());
    assert_eq!(output.execution.nullifiers(), sorted_nullifiers);

    assert_eq!(output.execution.private_actions.len(), 2);

    let sender_slot = output
        .execution
        .private_actions
        .iter()
        .position(|action| action.nullifier == sender_nullifier)
        .unwrap();
    let (_kind, sender_post) = EncryptionScheme::decrypt(
        &output.execution.private_actions[sender_slot]
            .encrypted_post_state
            .ciphertext,
        &shared_secret_1,
        &output.execution.private_actions[sender_slot].nullifier,
    )
    .unwrap();
    assert_eq!(sender_post, expected_private_account_1);

    let recipient_slot = output
        .execution
        .private_actions
        .iter()
        .position(|action| action.nullifier == recipient_nullifier)
        .unwrap();
    let (_kind, recipient_post) = EncryptionScheme::decrypt(
        &output.execution.private_actions[recipient_slot]
            .encrypted_post_state
            .ciphertext,
        &shared_secret_2,
        &output.execution.private_actions[recipient_slot].nullifier,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_private_account_2);
}

#[test]
fn note_ciphertext_is_padded_to_the_requested_length() {
    const PAD: u32 = 512;

    let keys = test_private_account_keys_1();
    let account_id = keys.account_id();
    let account =
        Account::default().with_actor_state(scripted_id(), ActorState::from(vec![9_u8; 200]));
    let expected_post_state = account.data.clone();
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let (padded, proof) = prove_scripted(
        PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            kind: WitnessKind::Regular(RegularKey::Authorized(keys.ask)),
            nullifier: NullifierWitness::Update {
                account,
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
            openings: BTreeSet::new(),
        },
        &Script::default(),
        Some(PAD),
    )
    .unwrap();

    assert!(proof.is_valid_for(&padded.context, &padded.execution));
    assert_eq!(padded.execution.private_actions.len(), 1);
    let ciphertext = &padded.execution.private_actions[0]
        .encrypted_post_state
        .ciphertext;
    assert_eq!(
        ciphertext.as_bytes().len(),
        usize::try_from(PAD).expect("pad fits in usize")
    );

    let shared_secret = SharedSecretKey::decapsulate(
        &padded.execution.private_actions[0].encrypted_post_state.epk,
        &keys.d,
        &keys.z,
    )
    .unwrap();
    let (kind, post) = EncryptionScheme::decrypt(
        ciphertext,
        &shared_secret,
        &padded.execution.private_actions[0].nullifier,
    )
    .unwrap();
    assert_eq!(kind, PrivateAccountKind::Regular);
    assert_eq!(post.data, expected_post_state);
}

#[test]
fn circuit_fails_when_transition_validity_windows_have_empty_intersection() {
    let account_keys = test_private_account_keys_1();
    let later = Script {
        response: Response::keep_state().try_block_window(4..7).unwrap(),
        ..Script::default()
    };
    let earlier = Script {
        response: Response::keep_state().try_block_window(1..4).unwrap(),
        ..Script::default()
    }
    .call(Actor::new(account_keys.account_id(), scripted_id()), &later);

    let result = prove_scripted(init_witness(&account_keys), &earlier, None);

    assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
}

/// A private PDA's initialization produces a ciphertext that decrypts to
/// `PrivateAccountKind::Pda` carrying its `(program_id, seed)`.
#[test]
fn private_pda_init_encrypts_its_pda_kind() {
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id = AccountId::for_private_pda(&scripted_id(), &seed, &npk, &keys.vpk());
    let init_nonce = Nonce::default().private_account_nonce_increment(&keys.nsk());
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let (output, _proof) = prove_scripted(
        init_pda_witness(&keys, (scripted_id(), seed)),
        &Script::default(),
        None,
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            account_id: scripted_id(),
            seed,
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
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
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
    let pda_id = AccountId::for_private_pda(&scripted_id(), &seed, &keys.npk(), &keys.vpk());

    // amount=0: the PDA has no balance yet
    let output = prove_pda_spend(
        pda_id,
        init_pda_witness(&keys, (scripted_id(), seed)),
        seed,
        0,
    )
    .expect("PDA withdraw should succeed");

    assert_eq!(output.execution.private_actions.len(), 1);
}

/// Builds a regular private account, returning its id, pre-state and a membership proof for its
/// commitment.
fn seeded_regular_account(
    keys: &TestPrivateKeys,
) -> (AccountId, Account, lee_core::MembershipProof) {
    let account_id = keys.account_id();
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
    let (_, account, membership_proof) = seeded_regular_account(&keys);

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
        kind: WitnessKind::Regular(RegularKey::Nullifying(keys.nsk())),
        nullifier: NullifierWitness::Update {
            account,
            membership_proof,
        },
        openings: BTreeSet::new(),
    }
}

#[test]
fn a_signer_entry_does_not_authorize_a_private_witness_without_ask() {
    let keys = test_private_account_keys_1();
    let (account_id, account, membership_proof) = seeded_regular_account(&keys);

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
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

/// A program that asserts authorization over its pre-states rejects a regular private account
/// whose witness supplied no `ask`.
#[test]
fn auth_asserting_program_rejects_unauthorized_regular_private_account() {
    let keys = test_private_account_keys_1();
    let (_, account, membership_proof) = seeded_regular_account(&keys);

    let result = prove_scripted(
        unauthorized_update(&keys, account, membership_proof),
        &Script::default().authorized(),
        None,
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

#[test]
fn a_signer_entry_does_not_authorize_a_private_pda() {
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id = AccountId::for_private_pda(&scripted_id(), &seed, &npk, &keys.vpk());

    let result = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(Vec::new(), [account_id]),
            private_witnesses: vec![init_pda_witness(&keys, (scripted_id(), seed))],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &Script::default().authorized(),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

#[test]
fn the_prover_never_reads_a_public_actor_state() {
    let account_id = AccountId::new([7; 32]);
    let root_actor = Actor::new(account_id, scripted_id());
    let callee = Actor::new(account_id, TWIN);
    let script = Script::default().call(callee, &Script::write(vec![3; 16]));

    // `Prover` supplies no public actor state, so executing either public transition would fail the
    // proof.
    let (output, proof) = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![root_actor, callee], []),
            ..proving_input(root(root_actor, &script))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();

    assert!(proof.is_valid_for(&output.context, &output.execution));
    assert_eq!(
        output.execution.public_root,
        Some(RootCall {
            to: root_actor,
            message: borsh::to_vec(&script).unwrap(),
        })
    );
    assert!(output.execution.boundary.is_empty());
}

#[test]
fn a_send_to_an_actor_the_transaction_never_declared_is_rejected() {
    let keys = test_private_account_keys_1();
    let undeclared = Actor::native_balance(AccountId::new([8; 32]));

    let result = prove_scripted(
        init_witness(&keys),
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
// private account, with the supplied responses standing in for its transitions.
fn direct_input(
    program_account_id: AccountId,
    script: &Script,
    claims: &[&Program],
    responses: Vec<Response>,
) -> PrivacyPreservingCircuitInput {
    let keys = test_private_account_keys_1();
    PrivacyPreservingCircuitInput {
        input: ProvingInput {
            root: root(Actor::new(keys.account_id(), program_account_id), script),
            context: PublicExecutionContext::default(),
            private_witnesses: vec![init_witness(&keys)],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_cast_promotions: BTreeSet::new(),
        },
        program_image_witnesses: claims_for(claims),
        shadow_program_witnesses: Vec::new(),
        responses,
        sender_presentations: Vec::new(),
        cast_seals: Vec::new(),
        predicted_cross_messages: Vec::new(),
    }
}

fn assert_circuit_rejects<T: std::fmt::Debug>(result: &Result<T, LeeError>, expected: &str) {
    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(msg)) if msg.contains(expected)),
        "expected the circuit to reject with {expected:?}, got {result:?}"
    );
}

// The root transition `direct_input` schedules for `script` on a `scripted` actor.
fn scripted_root_input(script: &Script, is_authorized: bool) -> ReceiveInput {
    let keys = test_private_account_keys_1();
    ReceiveInput {
        receiver: Actor::new(keys.account_id(), scripted_id()),
        from: None,
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

    assert_eq!(output.execution.private_actions.len(), 1);
    assert_eq!(output.execution.boundary, Boundary::default());
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
    let mut input = direct_input(scripted_id(), &script, &[&scripted], vec![response]);
    input
        .sender_presentations
        .push(SenderPresentation::Canonical);

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

    assert_circuit_rejects(&result, "a scheduled transition must carry its response");
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
        "A response was supplied for a transition nothing scheduled",
    );
}

#[test]
fn only_the_programs_the_private_part_runs_are_claimed() {
    let keys = test_private_account_keys_1();
    let root_actor = Actor::new(keys.account_id(), scripted_id());

    let (output, _) = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys)],
            ..proving_input(root(root_actor, &Script::default()))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();

    assert_eq!(
        output.execution.program_image_claims,
        vec![ProgramImageClaim::Disclosed {
            account_id: scripted_id(),
            image_id: crate::test_methods::scripted().id(),
        }]
    );
}

#[test]
fn preparation_meters_a_public_self_call_chain_as_settlement_does() {
    let revisited = Actor::new(BOB, scripted_id());
    let state = V03State::new()
        .with_empty_public_accounts([revisited.account_id])
        .with_programs([crate::test_methods::scripted()]);
    let tx = public_tx(
        revisited,
        vec![revisited],
        vec![],
        self_sends(revisited, 7),
        &[],
    );
    let settle = |cycle_budget| {
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &tx,
            &state,
            1,
            0,
            cycle_budget,
        )
        .map(|(_, charge)| charge.cycles)
    };
    let programs = scripted_programs();
    let simulate = |cycle_budget| -> Result<Cycles, LeeError> {
        let mut simulator = Simulator {
            programs: &programs.programs,
            public_actor_states: &HashMap::new(),
            admitted_accounts: None,
            recorder: SenderPresentationRecorder {
                choose: &mut |_| None,
                recorded: Vec::new(),
            },
            selector: CastPromotionSelector {
                select: &mut |_, _| false,
                from_public: PromotionSelection::new(BTreeSet::new()),
                from_private: PromotionSelection::new(BTreeSet::new()),
            },
            cycle_budget,
            cycles_used: 0,
        };
        WholeTransaction::new(
            tx.message.context.clone(),
            TransactionEntry::Call(tx.message.execution.root.clone()),
            &[],
        )?
        .execute(&mut simulator)?;
        Ok(simulator.cycles_used)
    };

    let total = settle(DEFAULT_PUBLIC_CYCLE_BUDGET).expect("the chain settles");
    assert_eq!(simulate(DEFAULT_PUBLIC_CYCLE_BUDGET).unwrap(), total);

    let budget = total.checked_div(2).unwrap();
    assert!(
        crate::test_methods::scripted()
            .handle_message(
                &ReceiveInput {
                    receiver: revisited,
                    from: None,
                    is_authorized: false,
                    pre_state: ActorState::empty(),
                    message: tx.message.execution.root.message.clone(),
                },
                budget,
            )
            .is_ok(),
        "the costliest call, the root, fits the budget alone"
    );
    assert!(matches!(settle(budget), Err(LeeError::OutOfGas { .. })));
    assert!(matches!(simulate(budget), Err(LeeError::OutOfGas { .. })));
}
