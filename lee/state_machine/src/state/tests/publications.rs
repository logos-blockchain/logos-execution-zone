use lee_core::{
    EncryptedNote, EphemeralSecretKey, FeeTransfer, MessageWitness, PrivateAccountKind,
    PublicationMode, Recipient, RecipientEncryption, RecoveryBinding,
    program::{MessageBody, Publication},
};

use super::*;
use crate::ValidatedStateDiff;

const OPENING: [u8; 32] = [9; 32];
const INBOX: AccountId = AccountId::new([4; 32]);
const FUNDS: Balance = 100;
const FEE: Balance = 10;
const PAID: Balance = 30;

fn sender() -> Actor {
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
        .with_empty_public_accounts([sender().account_id])
        .with_recovery_bindings([recovery(5).bind_recovery()])
}

fn publications(state: &V03State) -> Vec<(u64, Publication)> {
    state.publications_from(0).collect()
}

fn alice() -> AccountId {
    let keys = test_private_account_keys_2();
    AccountId::for_regular_private_account(&keys.npk(), &keys.vpk())
}

fn funded_state() -> V03State {
    V03State::new()
        .with_private_account(&test_private_account_keys_2(), &Account::funded(FUNDS))
        .with_empty_public_accounts([INBOX])
}

// Alice's private transfer of `PAID` to Bob's alias, its credit published clear and its fee paid to
// `INBOX`, proven against the funded note `state` holds for her.
fn clear_credit(state: &V03State) -> PrivacyPreservingTransaction {
    let funded = Account::funded(FUNDS);
    let proven = execute_and_prove(
        ProvingInput {
            public_context: PublicExecutionContext::new(vec![Actor::native_balance(INBOX)], []),
            private_witnesses: vec![update_witness(
                &test_private_account_keys_2(),
                funded.clone(),
                state
                    .get_proof_for_commitment(&Commitment::new(&alice(), &funded))
                    .expect("Alice's note must be in state"),
            )],
            fee: Some(FeeTransfer {
                payer: alice(),
                recipient: INBOX,
                amount: FEE,
                refund_to: None,
            }),
            ..proving_input(root(
                Actor::native_balance(alice()),
                &transfer(bob().address(), PAID),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        |bodies| Ok(bodies.iter().map(|_| PublicationMode::Clear).collect()),
    )
    .unwrap();
    private_tx(proven, vec![], &[])
}

// A proof whose public root runs `script` on the sender's account, its fee paid to `INBOX` from
// the funded note `state` holds for Alice.
fn fee_paying_public_root(state: &V03State, script: &Script) -> PrivacyPreservingTransaction {
    let funded = Account::funded(FUNDS);
    let proven = execute_and_prove(
        ProvingInput {
            public_context: PublicExecutionContext::new(
                vec![sender(), Actor::native_balance(INBOX)],
                [],
            ),
            private_witnesses: vec![update_witness(
                &test_private_account_keys_2(),
                funded.clone(),
                state
                    .get_proof_for_commitment(&Commitment::new(&alice(), &funded))
                    .expect("Alice's note must be in state"),
            )],
            fee: Some(FeeTransfer {
                payer: alice(),
                recipient: INBOX,
                amount: FEE,
                refund_to: None,
            }),
            ..proving_input(root(sender(), script))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();
    private_tx(proven, vec![], &[])
}

#[test]
fn a_public_root_publishes_its_live_async_message_with_the_recovery_note_its_proof_binds() {
    let mut state = V03State::new().with_test_programs();
    let tx = binding(
        &Script::default().send_async(payout(), &credit(7)),
        vec![recovery(5)],
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let note = state
        .recovery_binding(payout().account_id)
        .cloned()
        .expect("the proof binds the payout's recovery note");
    let page = state.publications_page(0, usize::MAX);
    let [(_, publication)] = <[_; 1]>::try_from(page.publications).unwrap();
    assert_eq!(
        publication,
        Publication::Clear(MessageBody {
            from: sender(),
            to: payout(),
            message: borsh::to_vec(&credit(7)).unwrap(),
        })
    );
    assert_eq!(
        page.recovery_bindings,
        BTreeMap::from([(payout().account_id, note)])
    );
    assert!(tx.message.execution.private_actions.is_empty());
    assert!(state.get_account_by_id_ref(payout().account_id).is_none());
}

#[test]
fn the_recipient_recovers_and_receives_an_async_message_at_an_alias_it_never_recorded() {
    let keys = test_private_account_keys_1();
    let mut state = V03State::new().with_test_programs();
    state
        .transition_from_privacy_preserving_transaction(
            &binding(
                &Script::default().send_async(payout(), &credit(7)),
                vec![recovery(5)],
            ),
            1,
            0,
        )
        .unwrap();
    let page = state.publications_page(0, usize::MAX);
    let [(position, Publication::Clear(body))] = <[_; 1]>::try_from(page.publications).unwrap()
    else {
        panic!("the async message to a private alias is published clear");
    };

    let note = &page.recovery_bindings[&body.to.account_id];
    let recovered = Recipient::recover(body.to.account_id, note, &keys.d, &keys.z).unwrap();
    assert_eq!(recovered, bob());
    let commitment = Commitment::for_message(&body);
    let membership_proof = state.get_proof_for_position(position).unwrap();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![PrivateWitness {
                address_openings: recovered.opening.into_iter().collect(),
                ..init_witness(&keys)
            }],
            ..proving_input(TransactionEntry::Async(MessageWitness {
                body,
                rho: None,
                membership_proof,
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
fn an_unproven_async_message_reuses_a_stored_recovery_note_byte_for_byte_whatever_its_body() {
    let mut state = bound_state();
    let note = state
        .recovery_binding(payout().account_id)
        .cloned()
        .expect("the state binds the payout's recovery note");

    state
        .transition_from_public_transaction(
            &public_tx(
                sender(),
                vec![sender()],
                vec![],
                Script::default()
                    .send_async(payout(), &credit(1))
                    .send_async(payout(), &credit(2)),
                &[],
            ),
            2,
            0,
        )
        .unwrap();

    let page = state.publications_page(0, usize::MAX);
    assert_eq!(
        page.publications
            .into_iter()
            .map(|(_, publication)| {
                let Publication::Clear(body) = publication else {
                    panic!("a public root publishes clear");
                };
                body.message
            })
            .collect::<Vec<_>>(),
        [1, 2].map(|amount| borsh::to_vec(&credit(amount)).unwrap())
    );
    assert_eq!(
        page.recovery_bindings,
        BTreeMap::from([(payout().account_id, note)])
    );
}

#[test]
fn a_durable_async_message_to_an_unbound_address_is_charged_and_publishes_nothing() {
    let unproven = Actor::new(AccountId::new([3; 32]), scripted_id());
    let other_program = Actor::new(sender().account_id, TWIN);
    for to in [payout(), unproven, other_program] {
        let mut state = V03State::new()
            .with_test_programs()
            .with_empty_public_accounts([sender().account_id]);
        let before = state.clone();
        let tx = public_tx(
            sender(),
            vec![sender()],
            vec![],
            Script::default().send_async(to, &credit(1)),
            &[],
        );
        let bound = before.clone().with_recovery_bindings([RecoveryBinding {
            address: to.account_id,
            note: EncryptedNote::default(),
        }]);
        let charged = |state: &V03State| {
            ValidatedStateDiff::from_public_transaction_metered(
                &tx,
                state,
                1,
                0,
                crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
            )
            .0
        };

        let result = state.transition_from_public_transaction(&tx, 1, 0);

        let Err(error) = result else {
            panic!("an async message to {to:?} must not publish");
        };
        assert!(
            matches!(error, LeeError::UnboundAsyncDestination { actor } if actor == to),
            "{error:?}"
        );
        assert!(error.is_chargeable());
        assert_eq!(state, before);
        // Bound, the same transaction publishes; unbound, it is charged the cycles that run took.
        let ran = charged(&bound);
        assert_eq!(ran.revert, None);
        assert_eq!(charged(&before).cycles, ran.cycles);
    }
}

#[test]
fn a_diff_publishing_clear_to_an_address_its_target_state_does_not_bind_is_refused_at_apply() {
    let mut target = V03State::new().with_test_programs();
    let tx = public_tx(
        sender(),
        vec![sender()],
        vec![],
        Script::default().send_async(payout(), &credit(1)),
        &[],
    );
    let diff = ValidatedStateDiff::from_public_transaction(&tx, &bound_state(), 2, 0).unwrap();
    let before = target.clone();

    assert!(matches!(
        target.apply_state_diff(diff),
        Err(LeeError::InvalidInput(message)) if message.starts_with("The recovery binding for ")
    ));
    assert_eq!(target, before);
}

#[test]
fn a_private_sender_pays_a_bound_alias_in_clear_and_the_alias_holder_receives_it_privately() {
    let keys = test_private_account_keys_1();
    let mut state = funded_state().with_recovery_bindings([recovery(5).bind_recovery()]);
    let tx = clear_credit(&state);
    assert!(
        tx.message.execution.recovery_bindings.is_empty(),
        "Alice's payment proves no recovery binding"
    );

    let (diff, charge) = ValidatedStateDiff::from_privacy_preserving_transaction_metered(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .unwrap();
    assert_eq!(charge.revert, None);
    state.apply_state_diff(diff).unwrap();

    let note = state
        .recovery_binding(bob().address())
        .cloned()
        .expect("the state binds Bob's alias");
    let page = state.publications_page(0, usize::MAX);
    let [(position, Publication::Clear(body))] = <[_; 1]>::try_from(page.publications).unwrap()
    else {
        panic!("a private sender's credit selected clear is published clear");
    };
    assert_eq!(
        body,
        MessageBody {
            from: Actor::native_balance(alice()),
            to: Actor::native_balance(bob().address()),
            message: borsh::to_vec(&NativeMessage::Credit(PAID)).unwrap(),
        }
    );
    assert_eq!(
        page.recovery_bindings,
        BTreeMap::from([(bob().address(), note.clone())])
    );
    assert_eq!(
        state.get_account_by_id(INBOX).data.native_balance(),
        Ok(FEE)
    );

    let recovered = Recipient::recover(body.to.account_id, &note, &keys.d, &keys.z).unwrap();
    assert_eq!(recovered, bob());
    let membership_proof = state.get_proof_for_position(position).unwrap();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![PrivateWitness {
                address_openings: recovered.opening.into_iter().collect(),
                ..init_witness(&keys)
            }],
            ..proving_input(TransactionEntry::Async(MessageWitness {
                body,
                rho: None,
                membership_proof,
                filler: DummyOutput::default(),
            }))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();
    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .unwrap();

    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(
                &recovered.account_id(),
                &Account {
                    nonce: Nonce::default().private_account_nonce_increment(&keys.nsk()),
                    ..Account::funded(PAID)
                },
            ))
            .is_some()
    );
}

#[test]
fn a_clear_credit_to_an_unbound_alias_reverts_its_transaction_to_the_fee_fallback() {
    let keys = test_private_account_keys_2();
    let mut state = funded_state();
    let tx = clear_credit(&state);

    let (diff, charge) = ValidatedStateDiff::from_privacy_preserving_transaction_metered(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .unwrap();
    assert_eq!(
        charge.revert,
        Some(
            LeeError::UnboundAsyncDestination {
                actor: Actor::native_balance(bob().address()),
            }
            .to_string()
        )
    );
    assert_eq!(charge.cycles, 0, "native execution is not metered");
    state.apply_state_diff(diff).unwrap();

    let alice_after = |balance| {
        Commitment::new(
            &alice(),
            &Account {
                nonce: Nonce::default().private_account_nonce_increment(&keys.nsk()),
                ..Account::funded(balance)
            },
        )
    };
    assert!(publications(&state).is_empty());
    assert!(
        state
            .get_proof_for_commitment(&alice_after(FUNDS - FEE))
            .is_some()
    );
    assert!(
        state
            .get_proof_for_commitment(&alice_after(FUNDS - FEE - PAID))
            .is_none()
    );
    assert_eq!(
        state.get_account_by_id(INBOX).data.native_balance(),
        Ok(FEE)
    );
}

#[test]
fn a_proofs_public_root_publishing_to_an_unbound_address_is_charged_the_cycles_it_ran() {
    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let mut unbound = funded_state()
        .with_test_programs()
        .with_empty_public_accounts([sender().account_id]);
    let bound = unbound
        .clone()
        .with_recovery_bindings([recovery(5).bind_recovery()]);
    let tx = fee_paying_public_root(
        &unbound,
        &Script::write(vec![1]).send_async(payout(), &credit(1)),
    );
    let settled = |state: &V03State| {
        ValidatedStateDiff::from_privacy_preserving_transaction_metered(&tx, state, 1, 0, budget)
            .unwrap()
    };

    let (bound_diff, bound_charge) = settled(&bound);
    let (diff, charge) = settled(&unbound);

    assert_eq!(bound_charge.revert, None);
    assert!(bound_diff.public_diff().contains_key(&sender().account_id));
    assert!(bound_charge.cycles > 0 && bound_charge.cycles < budget);
    assert_eq!(
        charge.revert,
        Some(LeeError::UnboundAsyncDestination { actor: payout() }.to_string())
    );
    assert_eq!(charge.cycles, bound_charge.cycles);
    assert!(!diff.public_diff().contains_key(&sender().account_id));
    unbound.apply_state_diff(diff).unwrap();
    assert!(publications(&unbound).is_empty());
    assert_eq!(
        unbound.get_account_by_id(INBOX).data.native_balance(),
        Ok(FEE)
    );
}
