use lee_core::{
    EphemeralSecretKey, MessageWitness, PrivateAccountKind, Recipient, RecipientEncryption,
    compute_digest_for_path,
    execution_state::Placement,
    program::{MessageBody, Publication},
};

use super::*;
use crate::ValidatedStateDiff;

// A publication as these tests read it back: its position in the log and its clear body.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    position: u64,
    body: MessageBody,
}

impl Record {
    fn commitment(&self) -> Commitment {
        Commitment::for_message(&self.body)
    }

    fn received_privately(&self, state: &V03State, keys: &TestPrivateKeys) -> bool {
        state.is_spent(&Nullifier::for_message(
            &keys.nsk(),
            &self.commitment(),
            self.position,
        ))
    }

    // Spends this record under `state`'s current root, with its receiving witness's key.
    fn privately(&self, state: &V03State) -> TransactionEntry<MessageWitness> {
        let (_, path) = state
            .get_proof_for_position(self.position)
            .expect("a published record has a membership path");
        TransactionEntry::Cast(MessageWitness {
            body: self.body.clone(),
            position: self.position,
            rho: None,
            path,
            // A fresh output per root, as a wallet draws one per receipt.
            filler: DummyOutput {
                commitment_seed: state.commitment_set_digest(),
                ..DummyOutput::default()
            },
        })
    }

    // The spend a private receipt of this record adds to its actions, proven against `state`'s
    // current root.
    fn private_spend(&self, state: &V03State, keys: &TestPrivateKeys) -> (Nullifier, [u8; 32]) {
        (
            Nullifier::for_message(&keys.nsk(), &self.commitment(), self.position),
            state.commitment_set_digest(),
        )
    }
}

fn sender() -> Actor {
    Actor::new(test_public_account_keys_1().account_id(), scripted_id())
}

fn receiver_pk() -> PublicKey {
    PublicKey::new_from_private_key(&PrivateKey::try_new([7; 32]).unwrap())
}

fn receiver() -> Actor {
    Actor::new(AccountId::from(&receiver_pk()), scripted_id())
}

fn received() -> Script {
    Script::write(b"received".to_vec()).from(scripted_id())
}

fn replying() -> Script {
    received().cast(sender(), &received())
}

// `sender()` runs `script`, publishing each Cast to a private receiver with its recovery binding.
fn casting(script: Script) -> PublicTransaction {
    let message =
        public_transaction::Message::try_new(sender(), vec![sender()], BTreeMap::new(), script)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

fn cast(state: &mut V03State, to: Actor) -> Record {
    cast_script(state, to, &received())
}

fn cast_script(state: &mut V03State, to: Actor, script: &Script) -> Record {
    state
        .transition_from_public_transaction(&casting(Script::default().cast(to, script)), 1, 0)
        .unwrap();
    records(state, 0).pop().unwrap()
}

fn records(state: &V03State, from_position: u64) -> Vec<Record> {
    state
        .publications_from(from_position)
        .filter_map(|(position, publication)| match publication {
            Publication::Clear { body, .. } => Some(Record { position, body }),
            Publication::Sealed(_) => None,
        })
        .collect()
}

fn recovery(kind: PrivateAccountKind) -> RecipientEncryption {
    let keys = test_private_account_keys_1();
    RecipientEncryption {
        recipient: Recipient {
            npk: keys.npk(),
            vpk: keys.vpk(),
            kind,
            opening: None,
        },
        esk: EphemeralSecretKey([5; 32]),
    }
}

fn bound(kind: PrivateAccountKind) -> V03State {
    sender_present().with_recovery_bindings([recovery(kind).bind_recovery()])
}

#[test]
fn a_proven_receipt_settles_only_where_its_record_is_pending() {
    let keys = test_private_account_keys_1();
    let private_receiver = private_actor();
    let mut empty = V03State::new().with_test_programs();
    empty
        .transition_from_privacy_preserving_transaction(
            &binding(
                &Script::default(),
                vec![recovery(PrivateAccountKind::Regular)],
            ),
            1,
            0,
        )
        .unwrap();
    let (mut holding, mut replaced) = (empty.clone(), empty.clone());
    let record = cast(&mut holding, private_receiver);
    let other = cast_script(&mut replaced, private_receiver, &replying());
    assert_eq!(record.position, other.position);
    let proven = prove_receipt(record.privately(&holding), init_witness(&keys)).unwrap();
    let tx = private_tx(proven, vec![], &[]);

    for mut mailbox in [empty, replaced] {
        let before = mailbox.clone();
        assert!(matches!(
            mailbox.transition_from_privacy_preserving_transaction(&tx, 2, 0),
            Err(LeeError::InvalidInput(message)) if message == "Unrecognized commitment set digest"
        ));
        assert_eq!(mailbox, before);
    }
    holding
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();

    assert!(record.received_privately(&holding, &keys));
}

#[test]
fn a_private_pda_receives_a_cast_without_a_grant() {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let pda = Actor::new(
        AccountId::for_private_pda(&scripted_id(), &seed, &keys.npk(), &keys.vpk()),
        scripted_id(),
    );
    let mut state = bound(PrivateAccountKind::Pda {
        account_id: scripted_id(),
        seed,
    });
    let record = cast(&mut state, pda);
    let proven = prove_receipt(
        record.privately(&state),
        init_pda_witness(&keys, (scripted_id(), seed)),
    )
    .unwrap();
    assert!(
        proven
            .0
            .execution
            .nullifiers()
            .contains(&record.private_spend(&state, &keys))
    );

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .expect("a private PDA must receive a cast by proof alone");

    assert!(record.received_privately(&state, &keys));
}

#[test]
fn a_pending_record_survives_a_borsh_round_trip_and_enters_the_genesis_fingerprint() {
    let mut state = bound(PrivateAccountKind::Regular);
    let fingerprint = state.genesis_fingerprint();

    cast(&mut state, private_actor());

    assert_eq!(
        borsh::from_slice::<V03State>(&borsh::to_vec(&state).unwrap()).unwrap(),
        state
    );
    assert_ne!(state.genesis_fingerprint(), fingerprint);
}

#[test]
fn the_genesis_fingerprint_changes_when_a_binding_is_rebound() {
    let keys = test_private_account_keys_1();
    let bound = |esk| {
        V03State::new()
            .with_recovery_bindings([RecipientEncryption {
                recipient: Recipient {
                    npk: keys.npk(),
                    vpk: keys.vpk(),
                    kind: PrivateAccountKind::Regular,
                    opening: None,
                },
                esk: EphemeralSecretKey(esk),
            }
            .bind_recovery()])
            .genesis_fingerprint()
    };

    assert_eq!(bound([5; 32]), bound([5; 32]));
    assert_ne!(bound([5; 32]), bound([6; 32]));
}

#[test]
fn pending_records_are_listed_in_position_order_from_any_position() {
    let mut state = bound(PrivateAccountKind::Regular);
    let published: Vec<Record> = std::iter::repeat_with(|| cast(&mut state, private_actor()))
        .take(5)
        .collect();

    for (index, record) in published.iter().enumerate() {
        assert_eq!(records(&state, record.position), published[index..]);
    }
    assert!(records(&state, published[4].position + 1).is_empty());
}

#[test]
fn a_private_receipt_root_that_calls_a_public_actor_needs_no_admission_evidence() {
    let keys = test_private_account_keys_1();
    let private_receiver = private_actor();
    let mut state =
        bound(PrivateAccountKind::Regular).with_empty_public_accounts([receiver().account_id]);
    let record = cast_script(
        &mut state,
        private_receiver,
        &received().call(receiver(), &Script::write(b"called".to_vec())),
    );
    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![receiver()], []),
            private_witnesses: vec![init_witness(&keys)],
            ..proving_input(record.privately(&state))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .expect("a private receipt root must need no admission evidence");

    assert!(record.received_privately(&state, &keys));
    assert_eq!(
        state
            .get_account_by_id(receiver().account_id)
            .data
            .actor_state(scripted_id()),
        &ActorState::from(b"called".to_vec())
    );
}

fn private_actor() -> Actor {
    let keys = test_private_account_keys_1();
    Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk()),
        scripted_id(),
    )
}

// The private root runs `root_script` beside `public_actors`, sealing each durable Cast to its own
// account.
fn proven_casting(root_script: &Script, public_actors: Vec<Actor>) -> PrivacyPreservingTransaction {
    let keys = test_private_account_keys_1();
    let own = Recipient {
        npk: keys.npk(),
        vpk: keys.vpk(),
        kind: PrivateAccountKind::Regular,
        opening: None,
    };
    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(public_actors, []),
            private_witnesses: vec![init_witness(&keys)],
            ..proving_input(root(private_actor(), root_script))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        |_| {
            Ok(RecipientEncryption {
                recipient: own.clone(),
                esk: EphemeralSecretKey([0; 32]),
            })
        },
    )
    .unwrap();
    private_tx(proven, vec![], &[])
}

#[test]
fn a_mixed_transaction_publishes_its_live_casts_before_its_proven_casts() {
    let mut state = bound(PrivateAccountKind::Regular);
    let live = Script::default().cast(private_actor(), &replying());
    let tx = proven_casting(
        &Script::default()
            .cast(private_actor(), &received())
            .call(sender(), &live),
        vec![sender()],
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();

    let [
        (_, Publication::Clear { body, .. }),
        (_, Publication::Sealed(_)),
    ] = <[_; 2]>::try_from(state.publications_from(0).collect::<Vec<_>>()).unwrap()
    else {
        panic!("the live Cast is published clear before the proven one, which is sealed");
    };
    assert_eq!(
        body,
        MessageBody {
            from: sender(),
            to: private_actor(),
            message: borsh::to_vec(&replying()).unwrap(),
        }
    );
}

// `sender()` runs `script` beside `to`, carrying `admission_evidence` and signed by `signers`.
fn delivering(
    to: Actor,
    script: Script,
    admission_evidence: Vec<PublicAccountEvidence>,
    nonces: Vec<Nonce>,
    signers: &[&PrivateKey],
) -> PublicTransaction {
    let message = public_transaction::Message {
        admission_evidence,
        ..public_transaction::Message::try_new(
            sender(),
            vec![sender(), to],
            signer_nonces(signers, nonces),
            script,
        )
        .unwrap()
    };
    let witness_set = public_transaction::WitnessSet::for_message(&message, signers);
    PublicTransaction::new(message, witness_set)
}

fn promoting(
    to: Actor,
    admission_evidence: Vec<PublicAccountEvidence>,
    nonces: Vec<Nonce>,
    signers: &[&PrivateKey],
) -> PublicTransaction {
    delivering(
        to,
        Script::default().cast(to, &Script::write(b"promoted".to_vec())),
        admission_evidence,
        nonces,
        signers,
    )
}

fn signing_receiver(state: &mut V03State, block_id: BlockId) {
    let key = PrivateKey::try_new([7; 32]).unwrap();
    let nonce = state.get_account_by_id(receiver().account_id).nonce;
    state
        .transition_from_public_transaction(
            &public_tx(
                receiver(),
                vec![receiver()],
                vec![nonce],
                Script::default(),
                &[&key],
            ),
            block_id,
            0,
        )
        .unwrap();
}

#[test]
fn a_cast_to_a_declared_public_actor_runs_at_once_for_every_kind_of_admitted_receiver() {
    let key = PrivateKey::try_new([7; 32]).unwrap();
    let seed = PdaSeed::new([42; 32]);
    let pda = Actor::new(
        AccountId::for_public_pda(&scripted_id(), &seed),
        scripted_id(),
    );
    let empty = V03State::new()
        .with_test_programs()
        .with_empty_public_accounts([sender().account_id]);
    let mut signed_before = empty.clone();
    signing_receiver(&mut signed_before, 1);
    let cases = [
        (
            "signer",
            empty.clone(),
            promoting(receiver(), vec![], vec![Nonce(0)], &[&key]),
            receiver(),
        ),
        (
            "key evidence",
            empty.clone(),
            promoting(
                receiver(),
                vec![PublicAccountEvidence::Key(receiver_pk())],
                vec![],
                &[],
            ),
            receiver(),
        ),
        (
            "PDA evidence",
            empty.clone(),
            promoting(
                pda,
                vec![PublicAccountEvidence::Pda {
                    program: scripted_id(),
                    seed,
                }],
                vec![],
                &[],
            ),
            pda,
        ),
        (
            "present",
            empty.with_empty_public_accounts([receiver().account_id]),
            promoting(receiver(), vec![], vec![], &[]),
            receiver(),
        ),
        (
            "signed before",
            signed_before,
            promoting(receiver(), vec![], vec![], &[]),
            receiver(),
        ),
    ];

    for (evidence, mut state, tx, to) in cases {
        state
            .transition_from_public_transaction(&tx, 2, 0)
            .unwrap_or_else(|error| panic!("{evidence}: {error:?}"));

        assert_eq!(
            state
                .get_account_by_id(to.account_id)
                .data
                .actor_state(scripted_id()),
            &ActorState::from(b"promoted".to_vec()),
            "{evidence}"
        );
        assert_eq!(state.publications_from(0).count(), 0, "{evidence}");
    }
}

#[test]
fn a_cast_to_a_declared_receiver_without_evidence_changes_nothing() {
    for (to, admission_evidence) in [
        (receiver(), vec![]),
        (
            private_actor(),
            vec![PublicAccountEvidence::Key(receiver_pk())],
        ),
    ] {
        let mut state = V03State::new()
            .with_test_programs()
            .with_empty_public_accounts([sender().account_id]);
        let before = state.clone();

        let result = state.transition_from_public_transaction(
            &promoting(to, admission_evidence, vec![], &[]),
            1,
            0,
        );

        assert!(matches!(
            execution_error(result),
            ExecutionError::UnadmittedPublicActor { actor } if actor == to
        ));
        assert_eq!(state, before);
    }
}

fn sender_present() -> V03State {
    V03State::new()
        .with_test_programs()
        .with_empty_public_accounts([sender().account_id])
}

#[test]
fn a_call_to_an_absent_public_account_needs_evidence_deriving_it() {
    let seed = PdaSeed::new([42; 32]);
    let pda = Actor::new(
        AccountId::for_public_pda(&scripted_id(), &seed),
        scripted_id(),
    );
    let stranger = PublicKey::new_from_private_key(&PrivateKey::try_new([8; 32]).unwrap());
    for (to, admission_evidence, admitted) in [
        (receiver(), vec![], false),
        (
            receiver(),
            vec![PublicAccountEvidence::Key(receiver_pk())],
            true,
        ),
        (
            receiver(),
            vec![PublicAccountEvidence::Key(stranger)],
            false,
        ),
        (
            pda,
            vec![PublicAccountEvidence::Pda {
                program: scripted_id(),
                seed,
            }],
            true,
        ),
        (
            pda,
            vec![PublicAccountEvidence::Pda {
                program: TWIN,
                seed,
            }],
            false,
        ),
    ] {
        let mut state = sender_present();
        let before = state.clone();

        let result = state.transition_from_public_transaction(
            &delivering(
                to,
                Script::default().call(to, &Script::write(b"called".to_vec())),
                admission_evidence,
                vec![],
                &[],
            ),
            1,
            0,
        );

        if admitted {
            result.unwrap();
            assert_eq!(
                state
                    .get_account_by_id(to.account_id)
                    .data
                    .actor_state(scripted_id()),
                &ActorState::from(b"called".to_vec())
            );
        } else {
            assert!(matches!(
                execution_error(result),
                ExecutionError::UnadmittedPublicActor { actor } if actor == to
            ));
            assert_eq!(state, before);
        }
    }
}

#[test]
fn an_account_its_first_empty_run_registers_is_reached_later_without_evidence() {
    let mut state = sender_present();
    let reach = |admission_evidence| {
        delivering(
            receiver(),
            Script::default().call(receiver(), &Script::default()),
            admission_evidence,
            vec![],
            &[],
        )
    };

    state
        .transition_from_public_transaction(
            &reach(vec![PublicAccountEvidence::Key(receiver_pk())]),
            1,
            0,
        )
        .unwrap();
    let registered = state.get_account_by_id_ref(receiver().account_id).cloned();
    state
        .transition_from_public_transaction(&reach(Vec::new()), 2, 0)
        .unwrap();

    assert_eq!(registered, Some(Account::default()));
}

#[test]
fn admission_evidence_admits_an_absent_account_without_authorizing_it() {
    let key = PrivateKey::try_new([7; 32]).unwrap();
    let spend = Script::default().call(receiver(), &Script::default().authorized());
    let mut state = sender_present();
    let before = state.clone();

    let evidenced = state.transition_from_public_transaction(
        &delivering(
            receiver(),
            spend.clone(),
            vec![PublicAccountEvidence::Key(receiver_pk())],
            vec![],
            &[],
        ),
        1,
        0,
    );

    assert!(
        matches!(evidenced, Err(LeeError::ProgramExecutionFailed(_))),
        "{evidenced:?}"
    );
    // A failed run registers nothing.
    assert_eq!(state, before);
    state
        .transition_from_public_transaction(
            &delivering(receiver(), spend, vec![], vec![Nonce(0)], &[&key]),
            1,
            0,
        )
        .unwrap();
}

#[test]
fn an_account_cleared_of_its_state_stays_registered_and_admitted() {
    let mut state = sender_present();
    state.force_insert_account(
        receiver().account_id,
        Account::default().with_actor_state(scripted_id(), b"held".to_vec().into()),
    );
    let writing = |bytes: &[u8]| {
        delivering(
            receiver(),
            Script::default().call(receiver(), &Script::write(bytes.to_vec())),
            vec![],
            vec![],
            &[],
        )
    };

    state
        .transition_from_public_transaction(&writing(b""), 1, 0)
        .unwrap();
    let cleared = state.get_account_by_id_ref(receiver().account_id).cloned();
    state
        .transition_from_public_transaction(&writing(b"again"), 2, 0)
        .unwrap();

    assert_eq!(cleared, Some(Account::default()));
}

#[test]
fn private_execution_reaches_a_pda_a_public_seed_admitted_earlier_without_evidence() {
    let seed = PdaSeed::new([42; 32]);
    let vault = Actor::new(
        AccountId::for_public_pda(&scripted_id(), &seed),
        scripted_id(),
    );
    let seeding = Script::default()
        .send(Call::new(vault, &Script::write(b"first".to_vec())).with_pda_seeds(vec![seed]));
    let direct = Script::write(b"second".to_vec());
    let settle = |root_script: Script| {
        let mut state = sender_present();
        state
            .transition_from_privacy_preserving_transaction(
                &proven_casting(&root_script, vec![sender(), vault]),
                1,
                0,
            )
            .map(|()| state.get_account_by_id(vault.account_id))
    };

    let reached = settle(
        Script::default()
            .call(sender(), &seeding)
            .call(vault, &direct),
    )
    .unwrap();
    let unseeded = settle(Script::default().call(vault, &direct));

    assert_eq!(
        reached.data.actor_state(scripted_id()),
        &ActorState::from(b"second".to_vec())
    );
    assert!(matches!(
        execution_error(unseeded),
        ExecutionError::UnadmittedPublicActor { actor } if actor == vault
    ));
}

#[test]
fn a_proven_call_to_an_unadmitted_public_account_is_refused_at_settlement() {
    let mut state = V03State::new().with_test_programs();
    let before = state.clone();
    let tx = proven_casting(
        &Script::default().call(receiver(), &Script::write(b"called".to_vec())),
        vec![receiver()],
    );

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(matches!(
        execution_error(result),
        ExecutionError::UnadmittedPublicActor { actor } if actor == receiver()
    ));
    assert_eq!(state, before);
}

#[test]
fn a_selected_candidate_the_transaction_never_reaches_is_refused() {
    let keys = test_private_account_keys_1();
    let input = |cast_promotions, private_cast_promotions| ProvingInput {
        context: PublicExecutionContext {
            cast_promotions,
            ..PublicExecutionContext::default()
        },
        private_witnesses: vec![init_witness(&keys)],
        private_cast_promotions,
        ..proving_input(root(private_actor(), &Script::default()))
    };
    let prove = |input| {
        execute_and_prove_with_cross_messages(
            input,
            Vec::new(),
            &scripted_programs(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            no_seal,
        )
    };
    let simulate = |input| {
        execute_and_prove(
            input,
            &Simulation::default(),
            &scripted_programs(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            no_seal,
        )
        .map(drop)
    };

    let unreached_privately = prove(input(BTreeSet::new(), BTreeSet::from([7])));
    let proven = prove(input(BTreeSet::from([7]), BTreeSet::new())).unwrap();
    let unreached_publicly = V03State::new()
        .with_test_programs()
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 1, 0);

    for result in [
        unreached_privately.map(drop),
        unreached_publicly.map(drop),
        simulate(input(BTreeSet::from([7]), BTreeSet::new())),
        simulate(input(BTreeSet::new(), BTreeSet::from([7]))),
    ] {
        assert!(matches!(
            execution_error(result),
            ExecutionError::UnreachedCastPromotion { index: 7 }
        ));
    }
}

#[test]
fn simulation_delivers_each_candidate_its_input_or_its_callback_selects() {
    let (keys, recipient_keys) = (test_private_account_keys_1(), test_private_account_keys_2());
    let recipient = Actor::new(
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk()),
        scripted_id(),
    );
    let root_script = Script::default()
        .cast(recipient, &received())
        .call(sender(), &Script::default().cast(recipient, &received()));

    for (given, selecting) in [
        (Placement::Public, Placement::Private),
        (Placement::Private, Placement::Public),
    ] {
        let selection = |placement| {
            if placement == given {
                BTreeSet::from([0])
            } else {
                BTreeSet::new()
            }
        };
        let (output, _) = execute_and_prove(
            ProvingInput {
                context: PublicExecutionContext {
                    cast_promotions: selection(Placement::Public),
                    ..PublicExecutionContext::new(vec![sender()], [])
                },
                private_witnesses: vec![init_witness(&keys), init_witness(&recipient_keys)],
                private_cast_promotions: selection(Placement::Private),
                ..proving_input(root(private_actor(), &root_script))
            },
            &Simulation::default(),
            &scripted_programs(),
            |_| SenderPresentation::Canonical,
            |placement, _| placement == selecting,
            no_seal,
        )
        .unwrap();

        assert_eq!(output.context.cast_promotions, BTreeSet::from([0]));
        assert!(output.execution.casts.is_empty());
        assert_eq!(output.execution.private_actions.len(), 2);
    }
}

// Proves `root` received by `witness`'s private account.
fn prove_receipt(
    root: TransactionEntry<MessageWitness>,
    witness: PrivateWitness,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    execute_and_prove(
        ProvingInput {
            private_witnesses: vec![witness],
            ..proving_input(root)
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
}

// Receives `record` privately into `witness`'s account.
fn receive_privately(
    state: &mut V03State,
    record: &Record,
    witness: PrivateWitness,
    block_id: BlockId,
) {
    let proven = prove_receipt(record.privately(state), witness).unwrap();
    state
        .transition_from_privacy_preserving_transaction(
            &private_tx(proven, vec![], &[]),
            block_id,
            0,
        )
        .unwrap();
}

// The private receiver's account once a `received()` message has initialized it.
fn received_account() -> Account {
    Account {
        nonce: Nonce::default()
            .private_account_nonce_increment(&test_private_account_keys_1().nsk()),
        ..Account::default().with_actor_state(scripted_id(), b"received".to_vec().into())
    }
}

// The private receiver's recorded account, as an update witness against `state`.
fn recorded_receiver(state: &V03State) -> PrivateWitness {
    let account = received_account();
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&private_actor().account_id, &account))
        .expect("a receipt has recorded the private receiver");
    update_witness(&test_private_account_keys_1(), account, membership_proof)
}

#[test]
fn a_private_receipt_discloses_only_its_root_and_nullifier_for_a_new_or_a_recorded_account() {
    let keys = test_private_account_keys_1();
    let mut state = bound(PrivateAccountKind::Regular);
    let first = cast(&mut state, private_actor());
    let second = cast(&mut state, private_actor());
    let receive = |state: &mut V03State, record: &Record, witness, block_id| {
        let (output, proof) = prove_receipt(record.privately(state), witness).unwrap();
        assert!(
            output.execution.public_root.is_none()
                && output
                    .execution
                    .nullifiers()
                    .contains(&record.private_spend(state, &keys))
        );
        assert_eq!(output.context, PublicExecutionContext::default());
        assert!(
            output.execution.boundary.is_empty()
                && output.execution.casts.is_empty()
                && output.execution.recovery_bindings.is_empty()
        );
        state
            .transition_from_privacy_preserving_transaction(
                &private_tx((output, proof), vec![], &[]),
                block_id,
                0,
            )
            .unwrap();
        assert!(record.received_privately(state, &keys));
    };

    // The first receipt initializes the receiver's account, and the second updates it.
    receive(&mut state, &first, init_witness(&keys), 2);
    let witness = recorded_receiver(&state);
    receive(&mut state, &second, witness, 3);

    assert!(state.is_spent(&Nullifier::for_account_update(
        &Commitment::new(&private_actor().account_id, &received_account()),
        &keys.nsk()
    )));
    assert_eq!(records(&state, 0), vec![first, second]);
}

#[test]
fn a_private_receipt_altered_in_body_path_or_position_is_refused() {
    let keys = test_private_account_keys_1();
    let mut state = bound(PrivateAccountKind::Regular);
    let record = cast(&mut state, private_actor());
    // A different body: an identical one at the sibling position would share the record's path, and
    // so be received there.
    let other = cast_script(&mut state, private_actor(), &replying());
    let TransactionEntry::Cast(honest) = record.privately(&state) else {
        panic!("a received record is a cast");
    };
    let mut forged_path = honest.path.clone();
    forged_path[0][0] ^= 1;
    let prove = |witness| prove_receipt(TransactionEntry::Cast(witness), init_witness(&keys));

    for (alteration, witness) in [
        (
            "body",
            MessageWitness {
                body: MessageBody {
                    from: Actor::new(AccountId::new([2; 32]), scripted_id()),
                    ..honest.body.clone()
                },
                ..honest.clone()
            },
        ),
        (
            "path",
            MessageWitness {
                path: forged_path,
                ..honest.clone()
            },
        ),
        (
            "position",
            MessageWitness {
                position: other.position,
                ..honest.clone()
            },
        ),
    ] {
        let proven = prove(witness).unwrap_or_else(|error| panic!("{alteration}: {error:?}"));
        let before = state.clone();

        let result = state.transition_from_privacy_preserving_transaction(
            &private_tx(proven, vec![], &[]),
            2,
            0,
        );

        assert!(
            matches!(
                result,
                Err(LeeError::InvalidInput(message))
                    if message == "Unrecognized commitment set digest"
            ),
            "{alteration}"
        );
        assert_eq!(state, before, "{alteration}");
    }

    state
        .transition_from_privacy_preserving_transaction(
            &private_tx(prove(honest).unwrap(), vec![], &[]),
            2,
            0,
        )
        .expect("the unaltered receipt must settle");
    assert!(record.received_privately(&state, &keys));
}

#[test]
fn a_privately_received_message_is_refused_when_received_privately_again() {
    let keys = test_private_account_keys_1();
    let mut state = bound(PrivateAccountKind::Regular);
    let record = cast(&mut state, private_actor());
    receive_privately(&mut state, &record, init_witness(&keys), 2);

    // Spent again under the grown tree's root, beside an account update whose own nullifier is
    // fresh: only the message's nullifier repeats.
    let again = private_tx(
        prove_receipt(record.privately(&state), recorded_receiver(&state)).unwrap(),
        vec![],
        &[],
    );
    assert!(!state.is_spent(&Nullifier::for_account_update(
        &Commitment::new(&private_actor().account_id, &received_account()),
        &keys.nsk()
    )));
    let before = state.clone();
    assert!(matches!(
        state.transition_from_privacy_preserving_transaction(&again, 3, 0),
        Err(LeeError::InvalidInput(message)) if message == "Nullifier already seen"
    ));
    assert_eq!(state, before);
}

#[test]
fn identical_casts_to_a_private_receiver_are_spent_independently() {
    let keys = test_private_account_keys_1();
    let mut state = bound(PrivateAccountKind::Regular);
    // A different message first, so the identical ones are not siblings.
    state
        .transition_from_public_transaction(
            &casting(
                Script::default()
                    .cast(private_actor(), &replying())
                    .cast(private_actor(), &received())
                    .cast(private_actor(), &received()),
            ),
            1,
            0,
        )
        .unwrap();
    let [_, first, second] = <[_; 3]>::try_from(records(&state, 0)).unwrap();
    assert_eq!(
        (&first.body, first.position + 1),
        (&second.body, second.position)
    );
    // Each is received with the path at its own position.
    let path = |record: &Record| {
        state
            .get_proof_for_position(record.position)
            .map(|(_, path)| path)
    };
    assert_ne!(path(&first), path(&second));

    receive_privately(&mut state, &second, init_witness(&keys), 2);
    assert!(second.received_privately(&state, &keys));
    assert!(!first.received_privately(&state, &keys));

    // Account leaves stay fresh: recording the receiver's account again is refused before any
    // nullifier is checked.
    let reinitialized = private_tx(
        prove_receipt(first.privately(&state), init_witness(&keys)).unwrap(),
        vec![],
        &[],
    );
    let before = state.clone();
    assert!(matches!(
        state.transition_from_privacy_preserving_transaction(&reinitialized, 3, 0),
        Err(LeeError::InvalidInput(message)) if message == "Commitment already seen"
    ));
    assert_eq!(state, before);

    let witness = recorded_receiver(&state);
    receive_privately(&mut state, &first, witness, 3);
    assert!(first.received_privately(&state, &keys));
}

#[test]
fn a_transaction_records_one_root_over_its_account_leaves_and_then_its_message_leaves() {
    let mut state = bound(PrivateAccountKind::Regular);
    let roots = |state: &V03State| state.private_state.0.root_history.len();
    let recorded = roots(&state);
    // The private root's account leaf, then its cast's message leaf.
    let tx = proven_casting(
        &Script::default().cast(private_actor(), &received()),
        Vec::new(),
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();

    let [(position, message)] = <[_; 1]>::try_from(
        state
            .publications_from(0)
            .map(|(position, publication)| (position, publication.commitment()))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let [account] = <[_; 1]>::try_from(tx.message.execution.commitments()).unwrap();
    let (index, path) = state.get_proof_for_commitment(&account).unwrap();
    assert_eq!(roots(&state), recorded + 1);
    assert_eq!(index + 1, position);
    assert_eq!(
        compute_digest_for_path(&account, index, &path),
        Ok(state.commitment_set_digest())
    );
    let (_, message_path) = state.get_proof_for_position(position).unwrap();
    assert_eq!(
        compute_digest_for_path(&message, position, &message_path),
        Ok(state.commitment_set_digest())
    );
    // A message leaf is found by its position alone.
    assert!(state.get_proof_for_commitment(&message).is_none());

    let live = cast(&mut state, private_actor());
    assert_eq!(live.position, position + 1);
    assert_eq!(roots(&state), recorded + 2);
}

#[test]
fn a_validated_private_receipt_is_refused_at_apply_once_its_message_is_spent_or_its_root_unknown() {
    let keys = test_private_account_keys_1();
    let publishing_twice = |script: &Script| {
        let mut state = bound(PrivateAccountKind::Regular);
        state
            .transition_from_public_transaction(
                &casting(
                    Script::default()
                        .cast(private_actor(), script)
                        .cast(private_actor(), script),
                ),
                1,
                0,
            )
            .unwrap();
        state
    };
    let published = publishing_twice(&received());
    let fork = publishing_twice(&replying());
    let [record, twin] = <[_; 2]>::try_from(records(&published, 0)).unwrap();
    let mut fresh = published.clone();
    receive_privately(&mut fresh, &twin, init_witness(&keys), 2);
    // As if received elsewhere, the record's message alone is spent, under every root `fresh` has.
    let mut spent = fresh.clone();
    spent.private_state.1.extend(&[Nullifier::for_message(
        &keys.nsk(),
        &record.commitment(),
        record.position,
    )]);
    let validate = |root, witness, state: &V03State| {
        let tx = private_tx(prove_receipt(root, witness).unwrap(), vec![], &[]);
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, state, 3, 0).unwrap()
    };
    let update = validate(record.privately(&fresh), recorded_receiver(&fresh), &fresh);
    let init = validate(
        record.privately(&published),
        init_witness(&keys),
        &published,
    );

    for (mut target, diff, refusal) in [
        (spent, update, "Nullifier already seen"),
        (fork, init, "Unrecognized commitment set digest"),
    ] {
        let before = target.clone();
        assert!(
            matches!(
                target.apply_state_diff(diff),
                Err(LeeError::InvalidInput(message)) if message == refusal
            ),
            "{refusal}"
        );
        assert_eq!(target, before);
    }
}

#[test]
fn a_private_receipt_whose_live_cast_cannot_settle_spends_nothing() {
    let keys = test_private_account_keys_1();
    let stranger = Actor::new(AccountId::new([9; 32]), scripted_id());
    let mut state =
        bound(PrivateAccountKind::Regular).with_empty_public_accounts([receiver().account_id]);
    let record = cast_script(
        &mut state,
        private_actor(),
        &received().call(
            receiver(),
            &Script::default().cast(stranger, &Script::default()),
        ),
    );
    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![receiver()], []),
            private_witnesses: vec![init_witness(&keys)],
            ..proving_input(record.privately(&state))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();
    let before = state.clone();

    let result = state.transition_from_privacy_preserving_transaction(
        &private_tx(proven, vec![], &[]),
        2,
        0,
    );

    assert!(
        matches!(result, Err(LeeError::UnboundCastDestination { actor }) if actor == stranger),
        "{result:?}"
    );
    assert_eq!(state, before);
}

#[test]
fn a_call_to_a_private_account_or_its_alias_declared_public_is_refused() {
    let alias = Actor::new(private_actor().account_id.blinded(&[6; 32]), scripted_id());
    for to in [private_actor(), alias] {
        let mut state = sender_present();
        let before = state.clone();

        let result = state.transition_from_public_transaction(
            &delivering(
                to,
                Script::default().call(to, &Script::write(b"called".to_vec())),
                vec![PublicAccountEvidence::Key(receiver_pk())],
                vec![],
                &[],
            ),
            1,
            0,
        );

        assert!(matches!(
            execution_error(result),
            ExecutionError::UnadmittedPublicActor { actor } if actor == to
        ));
        assert_eq!(state, before);
    }
}

#[test]
fn simulation_refuses_an_unadmitted_public_account_before_proving() {
    let result = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![sender()], []),
            ..proving_input(root(sender(), &Script::default()))
        },
        &Simulation {
            public_actor_states: HashMap::new(),
            admitted_accounts: Some(BTreeSet::new()),
        },
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::UnadmittedPublicActor { actor } if actor == sender()
    ));
}

#[test]
fn a_proof_under_explicit_predictions_delivers_the_private_cast_its_input_selects() {
    let (keys, recipient_keys) = (test_private_account_keys_1(), test_private_account_keys_2());
    let recipient = Actor::new(
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk()),
        scripted_id(),
    );

    let (output, _) = execute_and_prove_with_cross_messages(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys), init_witness(&recipient_keys)],
            private_cast_promotions: BTreeSet::from([0]),
            ..proving_input(root(
                private_actor(),
                &Script::default().cast(recipient, &received()),
            ))
        },
        Vec::new(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();

    assert!(output.execution.casts.is_empty());
    assert_eq!(output.execution.private_actions.len(), 2);
}
