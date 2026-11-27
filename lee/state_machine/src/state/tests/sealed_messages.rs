use lee_core::{
    EphemeralSecretKey, InvalidPublicationMode, MessageWitness, PrivateAccountKind,
    PublicationMode, Recipient, RecipientEncryption,
    program::{MessageBody, Publication},
};

use super::*;
use crate::ValidatedStateDiff;

fn sender() -> Actor {
    let keys = test_private_account_keys_1();
    Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk()),
        scripted_id(),
    )
}

fn recipient() -> Recipient {
    let keys = test_private_account_keys_2();
    Recipient {
        npk: keys.npk(),
        vpk: keys.vpk(),
        kind: PrivateAccountKind::Regular,
        opening: None,
    }
}

fn destination() -> Actor {
    Actor::new(recipient().address(), scripted_id())
}

fn sealed_to(
    recipient: Recipient,
) -> impl FnMut(&[MessageBody]) -> Result<Vec<PublicationMode>, LeeError> {
    move |bodies| {
        Ok(bodies
            .iter()
            .map(|_| {
                PublicationMode::Sealed(RecipientEncryption {
                    recipient: recipient.clone(),
                    esk: EphemeralSecretKey([0; 32]),
                })
            })
            .collect())
    }
}

// The sender's proof of sending a write asynchronously to the destination, published as
// `choose_publications` chooses.
fn proven_async_message(
    choose_publications: impl FnMut(&[MessageBody]) -> Result<Vec<PublicationMode>, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&test_private_account_keys_1())],
            ..proving_input(root(
                sender(),
                &Script::default().send_async(destination(), &Script::write(b"received".to_vec())),
            ))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        choose_publications,
    )
}

// The sender's proof of running `script`, which calls no public actor: through
// `execute_and_prove`, or through `execute_and_prove_with_cross_messages` given none.
fn proven_script(
    script: &Script,
    given_cross_messages: bool,
    choose_publications: impl FnMut(&[MessageBody]) -> Result<Vec<PublicationMode>, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let input = ProvingInput {
        private_witnesses: vec![init_witness(&test_private_account_keys_1())],
        ..proving_input(root(sender(), script))
    };
    if given_cross_messages {
        execute_and_prove_with_cross_messages(
            input,
            Vec::new(),
            &scripted_programs(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            choose_publications,
        )
    } else {
        execute_and_prove(
            input,
            &Simulation::default(),
            &scripted_programs(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            choose_publications,
        )
    }
}

#[test]
fn a_private_async_message_to_a_private_account_is_sealed_and_received_by_its_recipient_alone() {
    let keys = test_private_account_keys_2();
    let mut state = V03State::new().with_test_programs();
    let proven = proven_async_message(sealed_to(recipient())).unwrap();
    // Nothing the proof discloses names the destination.
    let address = destination().account_id;
    assert!(
        !proven
            .0
            .to_bytes()
            .windows(32)
            .any(|window| window == address.value())
    );

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 1, 0)
        .unwrap();

    let [(position, Publication::Sealed(sealed))] =
        <[_; 1]>::try_from(state.publications_from(0).collect::<Vec<_>>()).unwrap()
    else {
        panic!("the async message to a private account is sealed");
    };
    let sender_keys = test_private_account_keys_1();
    assert!(
        sealed
            .open(sender_keys.npk(), &sender_keys.d, &sender_keys.z)
            .is_none()
    );
    let (body, opened, rho) = sealed.open(keys.npk(), &keys.d, &keys.z).unwrap();
    assert_eq!((body.to, opened), (destination(), recipient()));

    let membership_proof = state.get_proof_for_position(position).unwrap();
    let receive = |rho| {
        let proven = execute_and_prove(
            ProvingInput {
                private_witnesses: vec![init_witness(&keys)],
                ..proving_input(TransactionEntry::Async(MessageWitness {
                    body: body.clone(),
                    rho,
                    membership_proof: membership_proof.clone(),
                    filler: DummyOutput::default(),
                }))
            },
            &Simulation::default(),
            &scripted_programs(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            no_seal,
        )
        .unwrap();
        private_tx(proven, vec![], &[])
    };
    let before = state.clone();
    // Without its randomness, the claim reaches a leaf no recorded root holds.
    assert!(matches!(
        state.transition_from_privacy_preserving_transaction(&receive(None), 2, 0),
        Err(LeeError::InvalidInput(message)) if message == "Unrecognized commitment set digest"
    ));
    assert_eq!(state, before);
    state
        .transition_from_privacy_preserving_transaction(&receive(Some(rho)), 2, 0)
        .expect("the recipient receives it with the commitment's randomness");

    assert!(state.is_spent(&Nullifier::for_message(
        &keys.nsk(),
        &sealed.commitment,
        position
    )));
}

#[test]
fn a_private_async_message_to_a_private_account_without_a_fitting_seal_fails_to_prove() {
    let stranger = Recipient {
        kind: PrivateAccountKind::Pda {
            account_id: scripted_id(),
            seed: PdaSeed::new([1; 32]),
        },
        ..recipient()
    };

    let result = proven_async_message(sealed_to(stranger));

    assert!(matches!(
        result,
        Err(LeeError::CircuitProvingError(message))
            if message.contains(&InvalidPublicationMode::MisaddressedSeal.to_string())
    ));
}

#[test]
fn a_tampered_sealed_message_is_rejected() {
    let state = V03State::new().with_test_programs();
    let mut tx = private_tx(
        proven_async_message(sealed_to(recipient())).unwrap(),
        vec![],
        &[],
    );
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified statement must verify"
    );

    let Publication::Sealed(sealed) = &mut tx.message.execution.async_messages[0] else {
        panic!("the async message to a private account is sealed");
    };
    sealed.note.epk.0[0] ^= 0xFF;

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}

#[test]
fn a_proof_asks_once_how_to_publish_its_durable_async_messages_even_when_it_sends_none() {
    let received = Script::write(b"received".to_vec());
    let sent = MessageBody {
        from: sender(),
        to: destination(),
        message: borsh::to_vec(&received).unwrap(),
    };
    for given_cross_messages in [false, true] {
        for (script, durable) in [
            (
                Script::default().send_async(destination(), &received),
                vec![sent.clone()],
            ),
            (Script::default(), Vec::new()),
        ] {
            let mut seal = sealed_to(recipient());
            let mut asked = Vec::new();

            proven_script(&script, given_cross_messages, |bodies| {
                asked.push(bodies.to_vec());
                seal(bodies)
            })
            .unwrap();

            assert_eq!(
                asked,
                [durable],
                "given cross messages: {given_cross_messages}"
            );
        }
    }
}

#[test]
fn a_refused_publication_stops_the_proof_even_of_no_durable_async_message() {
    let received = Script::write(b"received".to_vec());
    for given_cross_messages in [false, true] {
        for script in [
            Script::default().send_async(destination(), &received),
            Script::default(),
        ] {
            let result = proven_script(&script, given_cross_messages, |_| {
                Err(LeeError::InvalidInput("refused".to_owned()))
            });

            assert!(
                matches!(result, Err(LeeError::InvalidInput(message)) if message == "refused"),
                "given cross messages: {given_cross_messages}"
            );
        }
    }
}
