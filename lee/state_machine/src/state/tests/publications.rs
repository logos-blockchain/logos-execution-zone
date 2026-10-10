use lee_core::{
    EphemeralSecretKey, MessageWitness, PrivateAccountKind, Recipient, RecipientEncryption,
    program::{MessageBody, Publication},
};

use super::*;
use crate::ValidatedStateDiff;

const OPENING: [u8; 32] = [9; 32];

fn caster() -> Actor {
    Actor::new(test_public_account_keys_1().account_id(), scripted_id())
}

// Bob's account at the alias `OPENING` selects, an address Bob's records never held.
fn bob() -> Recipient {
    let keys = test_private_account_keys_1();
    Recipient {
        npk: keys.npk(),
        vpk: keys.vpk(),
        kind: PrivateAccountKind::Regular,
        opening: Some(OPENING),
    }
}

fn payout() -> Actor {
    Actor::new(bob().address(), scripted_id())
}

fn recovery(esk: u8) -> RecipientEncryption {
    RecipientEncryption {
        recipient: bob(),
        esk: EphemeralSecretKey([esk; 32]),
    }
}

fn credit(amount: u8) -> Script {
    Script::write(vec![amount]).from(scripted_id())
}

fn bound_state() -> V03State {
    V03State::new()
        .with_test_programs()
        .with_empty_public_accounts([caster().account_id])
        .with_recovery_bindings([recovery(5).bind_recovery()])
}

fn publications(state: &V03State) -> Vec<(u64, Publication)> {
    state.publications_from(0).collect()
}

#[test]
fn a_public_root_publishes_its_live_cast_with_the_recovery_note_its_proof_binds() {
    let mut state = V03State::new().with_test_programs();
    let tx = binding(
        &Script::default().cast(payout(), &credit(7)),
        vec![recovery(5)],
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let note = state
        .recovery_binding(payout().account_id)
        .cloned()
        .expect("the proof binds the payout's recovery note");
    let [(_, publication)] = <[_; 1]>::try_from(publications(&state)).unwrap();
    assert_eq!(
        publication,
        Publication::Clear {
            body: MessageBody {
                from: caster(),
                to: payout(),
                message: borsh::to_vec(&credit(7)).unwrap(),
            },
            recovery: note,
        }
    );
    assert!(tx.message.execution.private_actions.is_empty());
    assert!(state.get_account_by_id_ref(payout().account_id).is_none());
}

#[test]
fn the_recipient_recovers_and_receives_a_cast_at_an_alias_it_never_recorded() {
    let keys = test_private_account_keys_1();
    let mut state = V03State::new().with_test_programs();
    state
        .transition_from_privacy_preserving_transaction(
            &binding(
                &Script::default().cast(payout(), &credit(7)),
                vec![recovery(5)],
            ),
            1,
            0,
        )
        .unwrap();
    let [
        (
            position,
            Publication::Clear {
                body,
                recovery: note,
            },
        ),
    ] = <[_; 1]>::try_from(publications(&state)).unwrap()
    else {
        panic!("the cast to a private alias carries its recovery note");
    };

    let recovered = Recipient::recover(body.to.account_id, &note, &keys.d, &keys.z).unwrap();
    assert_eq!(recovered, bob());
    let commitment = Commitment::for_message(&body);
    let (_, path) = state.get_proof_for_position(position).unwrap();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![PrivateWitness {
                openings: recovered.opening.into_iter().collect(),
                ..init_witness(&keys)
            }],
            ..proving_input(TransactionEntry::Cast(MessageWitness {
                body,
                position,
                rho: None,
                path,
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
    assert!(proven.0.execution.nullifiers().contains(&(
        Nullifier::for_message(&keys.nsk(), &commitment, position),
        state.commitment_set_digest(),
    )));
    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .unwrap();

    let account_id = recovered.account_id();
    assert!(state.is_spent(&Nullifier::for_message(&keys.nsk(), &commitment, position)));
    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(
                &account_id,
                &Account {
                    nonce: Nonce::default().private_account_nonce_increment(&keys.nsk()),
                    ..Account::default().with_actor_state(scripted_id(), vec![7].into())
                },
            ))
            .is_some()
    );
}

#[test]
fn an_unproven_cast_reuses_a_stored_recovery_note_byte_for_byte_whatever_its_body() {
    let mut state = bound_state();
    let note = state
        .recovery_binding(payout().account_id)
        .cloned()
        .expect("the state binds the payout's recovery note");

    state
        .transition_from_public_transaction(
            &public_tx(
                caster(),
                vec![caster()],
                vec![],
                Script::default()
                    .cast(payout(), &credit(1))
                    .cast(payout(), &credit(2)),
                &[],
            ),
            2,
            0,
        )
        .unwrap();

    assert_eq!(
        publications(&state)
            .into_iter()
            .map(|(_, publication)| {
                let Publication::Clear { body, recovery } = publication else {
                    panic!("a public root publishes clear");
                };
                (body.message, recovery)
            })
            .collect::<Vec<_>>(),
        [1, 2].map(|amount| (borsh::to_vec(&credit(amount)).unwrap(), note.clone()))
    );
}

#[test]
fn a_durable_cast_to_an_unbound_address_is_charged_and_publishes_nothing() {
    let unproven = Actor::new(AccountId::new([3; 32]), scripted_id());
    let other_program = Actor::new(caster().account_id, TWIN);
    for to in [payout(), unproven, other_program] {
        let mut state = V03State::new()
            .with_test_programs()
            .with_empty_public_accounts([caster().account_id]);
        let before = state.clone();

        let result = state.transition_from_public_transaction(
            &public_tx(
                caster(),
                vec![caster()],
                vec![],
                Script::default().cast(to, &credit(1)),
                &[],
            ),
            1,
            0,
        );

        let Err(error) = result else {
            panic!("a cast to {to:?} must not publish");
        };
        assert!(
            matches!(error, LeeError::UnboundCastDestination { actor } if actor == to),
            "{error:?}"
        );
        assert!(error.is_chargeable());
        assert_eq!(state, before);
    }
}

#[test]
fn a_diff_carrying_a_recovery_note_its_target_state_does_not_bind_is_refused_at_apply() {
    let bound = bound_state();
    let unbound = V03State::new().with_test_programs();
    let rebound = unbound
        .clone()
        .with_recovery_bindings([recovery(6).bind_recovery()]);
    let tx = public_tx(
        caster(),
        vec![caster()],
        vec![],
        Script::default().cast(payout(), &credit(1)),
        &[],
    );

    for mut target in [unbound, rebound] {
        let diff = ValidatedStateDiff::from_public_transaction(&tx, &bound, 2, 0).unwrap();
        let before = target.clone();

        assert!(matches!(
            target.apply_state_diff(diff),
            Err(LeeError::InvalidInput(message)) if message.starts_with("The recovery binding for ")
        ));
        assert_eq!(target, before);
    }
}
