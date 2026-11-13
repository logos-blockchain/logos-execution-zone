use lee_core::signing_key::{SignatureMessage, SigningKeyState, signature_program_id};

use super::*;
use crate::{ValidatedStateDiff, signature::program::SetKeyError};

fn native_transfer_tx(
    sender: AccountId,
    receiver: AccountId,
    nonces: Vec<Nonce>,
    amount: u128,
    signers: &[&TestSigner],
) -> PublicTransaction {
    let from = Actor::native_balance(sender);
    let to = Actor::native_balance(receiver);
    public_tx(
        from,
        vec![from, to],
        nonces,
        transfer(receiver, amount),
        signers,
    )
}

#[test]
fn program_should_fail_if_it_debits_an_unauthorized_account() {
    let sender_account_id = AccountId::new([1; 32]);
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new().with_public_account_balances([(sender_account_id, 100)]);
    let tx = native_transfer_tx(sender_account_id, receiver_account_id, vec![], 1, &[]);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::UnauthorizedSender {
                    account_id: err_account_id
                }
            )
        )) if err_account_id == sender_account_id
    ));
}

#[test]
fn program_should_transfer_balance_from_an_authorized_account() {
    let sender_key = TestSigner::new(3);
    let sender_account_id = sender_key.account_id();
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(sender_account_id, 100), (receiver_account_id, 0)]);
    let tx = native_transfer_tx(
        sender_account_id,
        receiver_account_id,
        vec![Nonce(0)],
        1,
        &[&sender_key],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state
            .get_account_by_id(sender_account_id)
            .data
            .native_balance(),
        Ok(99)
    );
    assert_eq!(
        state
            .get_account_by_id(receiver_account_id)
            .data
            .native_balance(),
        Ok(1)
    );
}

#[test]
fn a_data_write_on_the_executing_actor_state_is_accepted_publicly() {
    let target_id = AccountId::new([1; 32]);
    let mut state = V03State::new()
        .with_public_accounts([(target_id, Account::funded(250))])
        .with_programs([crate::test_methods::scripted()]);
    let program_id = scripted_id();
    let written = vec![7_u8; 4];

    let writer = Actor::new(target_id, program_id);
    let tx = public_tx(
        writer,
        vec![writer],
        vec![],
        Script::write(written.clone()),
        &[],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    // Funded beforehand, so the whole-account assertion also pins that an application write
    // leaves the native balance actor state alone.
    assert_eq!(
        state.get_account_by_id(target_id),
        Account::funded(250).with_actor_state(program_id, written.into())
    );
}

/// A send may only name an actor the transaction declared — never an arbitrary account that
/// merely exists (or not) in global state.
#[test]
fn program_should_fail_if_it_references_an_undeclared_account() {
    let account_id = AccountId::new([1; 32]);
    let undeclared_account_id = AccountId::new([99; 32]);
    let undeclared = Actor::new(undeclared_account_id, scripted_id());
    // Existing in global state does not make an undeclared account reachable.
    for balances in [
        vec![(account_id, 0)],
        vec![(account_id, 0), (undeclared_account_id, 99)],
    ] {
        let mut state = V03State::new()
            .with_public_account_balances(balances)
            .with_programs([crate::test_methods::scripted()]);
        let sender = Actor::new(account_id, scripted_id());
        let tx = public_tx(
            sender,
            vec![sender],
            vec![],
            Script::default().send_sync(undeclared, &Script::default()),
            &[],
        );

        let result = state.transition_from_public_transaction(&tx, 1, 0);

        assert!(
            matches!(
                result,
                Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(
                    ExecutionError::UndeclaredActor { actor }
                ))) if actor == undeclared
            ),
            "expected UndeclaredActor for the undeclared actor, got {result:?}"
        );
    }
}

#[test]
fn a_public_transaction_rejects_a_transition_forging_any_echoed_field() {
    let program_id = AccountId::from_builtin_program(crate::test_methods::forges_echo().id());
    let forger = Actor::new(AccountId::new([1; 32]), program_id);
    for field in [
        ForgeField::Receiver,
        ForgeField::Sender,
        ForgeField::IsAuthorized,
        ForgeField::PreState,
        ForgeField::Message,
    ] {
        let mut state = V03State::new()
            .with_empty_public_accounts([forger.account_id])
            .with_programs([crate::test_methods::forges_echo()]);
        let tx = public_tx(forger, vec![forger], vec![], field, &[]);

        let result = state.transition_from_public_transaction(&tx, 1, 0);

        assert!(
            matches!(
                &result,
                Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(
                    ExecutionError::TransitionInputMismatch {
                        program_account_id,
                        ..
                    }
                ))) if *program_account_id == program_id
            ),
            "expected the forged echo to be rejected, got {result:?}"
        );
    }
}

#[test]
fn insufficient_balance_transfer_leaves_state_untouched() {
    let from_key = TestSigner::new(21);
    let from = from_key.account_id();
    let initial_balance = 10;
    let mut state = V03State::new().with_public_account_balances([(from, initial_balance)]);

    let to_key = TestSigner::new(22);
    let to = to_key.account_id();
    let amount: u128 = initial_balance + 1;

    let sender_pre = state.get_account_by_id(from);
    let recipient_pre = state.get_account_by_id(to);

    let tx = native_transfer_tx(
        from,
        to,
        vec![Nonce(0), Nonce(0)],
        amount,
        &[&from_key, &to_key],
    );

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::InsufficientBalance { account_id }
            )
        )) if account_id == from
    ));

    assert_eq!(state.get_account_by_id(from), sender_pre);
    assert_eq!(state.get_account_by_id(to), recipient_pre);
}

#[test]
fn a_sent_transition_on_another_actor_state_of_the_root_account_keeps_its_other_actor_states() {
    let account_id = AccountId::new([1; 32]);
    let stranger = AccountId::new([9; 32]);
    let on_chain: ActorState = b"on-chain".to_vec().into();
    let stranger_data: ActorState = b"stranger".to_vec().into();
    let written = vec![7; 4];
    let mut state = V03State::new()
        .with_public_accounts([(
            account_id,
            Account {
                nonce: Nonce(3),
                ..Account::funded(5)
                    .with_actor_state(TWIN, on_chain)
                    .with_actor_state(stranger, stranger_data.clone())
            },
        )])
        .with_test_programs();

    let sender = Actor::new(account_id, scripted_id());
    let callee = Actor::new(account_id, TWIN);
    let tx = public_tx(
        sender,
        vec![sender, callee],
        vec![],
        Script::default().send_sync(callee, &Script::write(written.clone())),
        &[],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(account_id),
        Account {
            nonce: Nonce(3),
            ..Account::funded(5)
                .with_actor_state(TWIN, written.into())
                .with_actor_state(stranger, stranger_data)
        }
    );
}

#[test]
fn a_declared_account_no_transition_changes_stays_out_of_the_diff_and_the_state() {
    let root = Actor::new(AccountId::new([41; 32]), scripted_id());
    let bystander = Actor::new(AccountId::new([42; 32]), scripted_id());
    let mut state = V03State::new()
        .with_test_programs()
        .with_empty_public_accounts([root.account_id]);
    let tx = public_tx(root, vec![root, bystander], vec![], Script::default(), &[]);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).unwrap();

    assert!(diff.public_diff().is_empty());
    state.apply_state_diff(diff).unwrap();
    assert!(state.get_account_by_id_ref(bystander.account_id).is_none());
}

/// A guest planted at the signature address never runs publicly: every public message there goes
/// to the native handler, as it does once the real guest is deployed.
fn planted_signature_program() -> V03State {
    V03State::new()
        .with_programs([crate::test_methods::scripted()])
        .with_programs_at([(
            signature_program_id(),
            crate::test_methods::scripted(),
            true,
        )])
}

fn set_key(next: SigningKeyState) -> SignatureMessage {
    SignatureMessage::SetKey { next }
}

/// Refused as a foreign sender, charged and reverted: the signer's nonce advances and its own
/// witness rotation still applies.
fn assert_charged_as_a_foreign_sender(
    mut state: V03State,
    tx: &PublicTransaction,
    signer: &TestSigner,
) -> V03State {
    let error = ValidatedStateDiff::from_public_transaction(tx, &state, 1, 0)
        .err()
        .expect("a message to the signature program from a foreign sender must fail");
    assert!(
        matches!(
            error,
            LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::SetKeyFailed(
                SetKeyError::ForeignSender
            ))
        ),
        "expected a foreign sender, got {error:?}"
    );

    let (charge, result) = ValidatedStateDiff::from_public_transaction_metered(
        tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    );

    assert_eq!(charge.revert, Some(error.to_string()));
    let diff = result.expect("a charged failure still yields an applicable diff");
    state.apply_state_diff(diff).unwrap();
    assert_eq!(
        state.get_account_by_id(signer.account_id()),
        Account {
            nonce: Nonce(1),
            ..Account::default()
        }
        .with_actor_state(signature_program_id(), signer.key_state(Nonce(1)).into())
    );
    state
}

#[test]
fn a_root_call_to_the_signature_program_is_charged_and_reverted() {
    let key = TestSigner::new(1);
    let signature = Actor::new(key.account_id(), signature_program_id());
    let tx = public_tx(
        signature,
        vec![signature],
        vec![Nonce(0)],
        Script::default(),
        &[&key],
    );

    assert_charged_as_a_foreign_sender(planted_signature_program(), &tx, &key);
}

#[test]
fn a_chained_call_to_the_signature_program_is_charged_and_reverted() {
    let key = TestSigner::new(1);
    let sender = Actor::new(key.account_id(), scripted_id());
    let signature = Actor::new(key.account_id(), signature_program_id());
    let tx = public_tx(
        sender,
        vec![sender, signature],
        vec![Nonce(0)],
        Script::write(vec![7; 4]).send_sync(signature, &Script::default()),
        &[&key],
    );

    assert_charged_as_a_foreign_sender(planted_signature_program(), &tx, &key);
}

#[test]
fn an_async_message_to_the_signature_program_is_charged_and_reverted() {
    let key = TestSigner::new(1);
    let sender = Actor::new(key.account_id(), scripted_id());
    let signature = Actor::new(key.account_id(), signature_program_id());
    let tx = public_tx(
        sender,
        vec![sender, signature],
        vec![Nonce(0)],
        Script::write(vec![7; 4]).send_async(signature, &Script::default()),
        &[&key],
    );

    assert_charged_as_a_foreign_sender(planted_signature_program(), &tx, &key);
}

#[test]
fn a_public_program_cannot_send_set_key() {
    let key = TestSigner::new(1);
    let victim = TestSigner::new(2);
    let victim_key = victim.key_state(Nonce(3));
    let state = planted_signature_program().with_public_accounts([(
        victim.account_id(),
        Account {
            nonce: Nonce(3),
            ..Account::default()
        }
        .with_actor_state(signature_program_id(), victim_key.into()),
    )]);
    let sender = Actor::new(key.account_id(), scripted_id());
    let target = Actor::new(victim.account_id(), signature_program_id());
    let tx = public_tx(
        sender,
        vec![sender, target],
        vec![Nonce(0)],
        Script::default().send_sync(target, &set_key(key.key_state(Nonce(0)))),
        &[&key],
    );

    let state = assert_charged_as_a_foreign_sender(state, &tx, &key);
    assert_eq!(
        state
            .get_account_by_id(victim.account_id())
            .data
            .actor_state(signature_program_id()),
        &ActorState::from(victim_key)
    );
}

#[test]
fn an_account_cannot_set_its_own_key_by_message() {
    let key = TestSigner::new(1);
    let sender = Actor::new(key.account_id(), scripted_id());
    let signature = Actor::new(key.account_id(), signature_program_id());
    let other_key = TestSigner::new(2).key_state(Nonce(0));
    let tx = public_tx(
        sender,
        vec![sender, signature],
        vec![Nonce(0)],
        Script::default().send_sync(signature, &set_key(other_key)),
        &[&key],
    );

    assert_charged_as_a_foreign_sender(planted_signature_program(), &tx, &key);
}
