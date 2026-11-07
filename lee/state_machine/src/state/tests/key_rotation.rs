use lee_core::{FeeTransfer, signing_key::SIGNATURE_PROGRAM_ID};

use super::*;
use crate::{
    PublicKey, ValidatedStateDiff,
    signature::{AuthError, authenticate},
};

const FEE: Balance = 5;
const FEE_INBOX: AccountId = AccountId::new([0xFE; 32]);

fn stored_key(state: &V03State, account_id: AccountId) -> ActorState {
    state
        .get_account_by_id(account_id)
        .data
        .actor_state(SIGNATURE_PROGRAM_ID)
        .clone()
}

fn key_at(signer: &TestSigner, nonce: u128) -> ActorState {
    signer.key_state(Nonce(nonce)).into()
}

fn assert_refused<T>(result: Result<T, LeeError>, signer: AccountId, reason: &str) {
    let expected = format!("Signer {signer} fails authentication: {reason}");
    match result {
        Err(LeeError::InvalidInput(message)) => assert_eq!(message, expected),
        Err(other) => panic!("expected `{expected}`, got {other:?}"),
        Ok(_) => panic!("expected `{expected}`, got a valid transaction"),
    }
}

// What authenticating a signer at nonce 0 fails with once its authentication data is changed at
// `position`: past the signature, the revealed key no longer gives its account id, if it is a key.
fn tampered_reason(auth_data: &[u8], position: usize) -> &'static str {
    if position < 64 {
        return "invalid signature";
    }
    let revealed = auth_data[64..].try_into().unwrap();
    if PublicKey::try_new(revealed).is_ok() {
        "revealed key does not give the account id"
    } else {
        "malformed authentication data"
    }
}

fn native_transfer(
    sender: &TestSigner,
    recipient: AccountId,
    nonce: Nonce,
    amount: Balance,
) -> PublicTransaction {
    let from = Actor::native_balance(sender.account_id());
    public_tx(
        from,
        vec![from, Actor::native_balance(recipient)],
        vec![nonce],
        transfer(recipient, amount),
        &[sender],
    )
}

// Moves `amount` from the first signer's public balance into a new private account under
// `recipient`, co-signed by the other signers, each at its nonce in `state`.
fn privacy_shield(
    state: &V03State,
    signers: &[&TestSigner],
    recipient: &TestPrivateKeys,
    amount: Balance,
) -> PrivacyPreservingTransaction {
    let sender = Actor::native_balance(signers[0].account_id());
    let proven = execute_and_prove(
        ProvingInput {
            public_context: PublicExecutionContext::new(
                vec![sender],
                signers.iter().map(|signer| signer.account_id()),
            ),
            private_witnesses: vec![init_witness(recipient)],
            ..proving_input(root(sender, &transfer(recipient.account_id(), amount)))
        },
        &Simulation {
            public_actor_states: [(sender, encode_balance(amount))].into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| true,
        no_seal,
    )
    .unwrap();
    private_tx(
        proven,
        signers
            .iter()
            .map(|signer| state.get_account_by_id(signer.account_id()).nonce)
            .collect(),
        signers,
    )
}

// A public root moving `amount` from `signer` to `recipient`, proven as if the signer held exactly
// `amount`, its fee paid from the private `payer` account into `FEE_INBOX`.
fn privacy_transfer_paying_privately(
    state: &V03State,
    signer: &TestSigner,
    recipient: AccountId,
    amount: Balance,
    payer: &TestPrivateKeys,
    payer_account: &Account,
) -> PrivacyPreservingTransaction {
    let sender = Actor::native_balance(signer.account_id());
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&payer.account_id(), payer_account))
        .expect("the payer's commitment is in state");
    let proven = execute_and_prove(
        ProvingInput {
            public_context: PublicExecutionContext::new(
                vec![
                    sender,
                    Actor::native_balance(recipient),
                    Actor::native_balance(FEE_INBOX),
                ],
                [signer.account_id()],
            ),
            private_witnesses: vec![update_witness(
                payer,
                payer_account.clone(),
                membership_proof,
            )],
            fee: Some(FeeTransfer {
                payer: payer.account_id(),
                recipient: FEE_INBOX,
                amount: FEE,
                refund_to: None,
            }),
            ..proving_input(root(sender, &transfer(recipient, amount)))
        },
        &Simulation {
            public_actor_states: [(sender, encode_balance(amount))].into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();
    private_tx(
        proven,
        vec![state.get_account_by_id(signer.account_id()).nonce],
        &[signer],
    )
}

#[test]
fn public_a_signer_at_nonce_zero_authenticates_with_the_key_giving_its_account_id() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let mut state =
        V03State::new().with_public_account_balances([(sender.account_id(), 100), (recipient, 0)]);

    state
        .transition_from_public_transaction(
            &native_transfer(&sender, recipient, Nonce(0), 30),
            1,
            0,
        )
        .unwrap();

    assert_eq!(state.get_account_by_id(sender.account_id()).nonce, Nonce(1));
    assert_eq!(stored_key(&state, sender.account_id()), key_at(&sender, 1));
}

#[test]
fn public_a_signer_at_nonce_zero_is_refused_a_key_not_giving_its_account_id() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state =
        V03State::new().with_public_account_balances([(sender.account_id(), 100), (recipient, 0)]);
    let honest = native_transfer(&sender, recipient, Nonce(0), 30);

    // Another account's key, and the account's own key for a later nonce.
    for (holder, nonce) in [(TestSigner::new(53), 0), (sender.clone(), 1)] {
        let mut tx = honest.clone();
        let message_with_keys = tx
            .message
            .message_with_keys(&[holder.key_state(Nonce(nonce + 1))]);
        tx.witness_set.entries = vec![holder.entry(Nonce(nonce), &message_with_keys)];

        assert_refused(
            ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0),
            sender.account_id(),
            "revealed key does not give the account id",
        );
    }
}

#[test]
fn public_a_tampered_byte_in_any_signers_authentication_data_is_refused() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = transfer_transaction(a.account_id(), &a, 0, b.account_id(), &b, 0, 30);
    assert!(ValidatedStateDiff::from_public_transaction(&honest, &state, 1, 0).is_ok());

    for (index, signer) in honest.signer_account_ids().into_iter().enumerate() {
        for position in 0..96 {
            let mut tx = honest.clone();
            tx.witness_set.entries[index].auth_data[position] ^= 1;
            let reason = tampered_reason(&tx.witness_set.entries[index].auth_data, position);

            assert_refused(
                ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0),
                signer,
                reason,
            );
        }
    }
}

#[test]
fn public_a_successful_transaction_rotates_every_signers_key_and_advances_its_nonce() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let mut state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);

    state
        .transition_from_public_transaction(
            &transfer_transaction(a.account_id(), &a, 0, b.account_id(), &b, 0, 30),
            1,
            0,
        )
        .unwrap();

    for (signer, balance) in [(&a, 70), (&b, 30)] {
        let account = state.get_account_by_id(signer.account_id());
        assert_eq!(account.data.native_balance(), Ok(balance));
        assert_eq!(account.nonce, Nonce(1));
        assert_eq!(
            account.data.actor_state(SIGNATURE_PROGRAM_ID),
            &key_at(signer, 1)
        );
    }
}

#[test]
fn public_a_charged_revert_drops_the_effects_but_rotates_every_signers_key_and_advances_its_nonce()
{
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let mut state =
        V03State::new().with_public_account_balances([(a.account_id(), 10), (b.account_id(), 7)]);
    let tx = transfer_transaction(a.account_id(), &a, 0, b.account_id(), &b, 0, 11);
    let error = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .err()
        .expect("the overdraft fails");
    assert!(
        matches!(
            &error,
            LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::InsufficientBalance { account_id }
            )) if *account_id == a.account_id()
        ),
        "{error:?}"
    );

    let (charge, result) = ValidatedStateDiff::from_public_transaction_metered(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    );
    assert_eq!(charge.revert, Some(error.to_string()));
    state
        .apply_state_diff(result.expect("a charged revert still yields an applicable diff"))
        .unwrap();

    for (signer, balance) in [(&a, 10), (&b, 7)] {
        let account = state.get_account_by_id(signer.account_id());
        assert_eq!(account.data.native_balance(), Ok(balance));
        assert_eq!(account.nonce, Nonce(1));
        assert_eq!(
            account.data.actor_state(SIGNATURE_PROGRAM_ID),
            &key_at(signer, 1)
        );
    }
}

#[test]
fn public_the_next_transaction_authenticates_with_the_new_key_and_the_old_key_is_refused() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let mut state =
        V03State::new().with_public_account_balances([(sender.account_id(), 100), (recipient, 0)]);
    state
        .transition_from_public_transaction(
            &native_transfer(&sender, recipient, Nonce(0), 10),
            1,
            0,
        )
        .unwrap();

    let next = native_transfer(&sender, recipient, Nonce(1), 10);
    let mut with_old_key = next.clone();
    let message_with_keys = next
        .message
        .message_with_keys(&[sender.key_state(Nonce(1))]);
    with_old_key.witness_set.entries = vec![sender.entry(Nonce(0), &message_with_keys)];
    assert_refused(
        ValidatedStateDiff::from_public_transaction(&with_old_key, &state, 2, 0),
        sender.account_id(),
        "invalid signature",
    );

    state
        .transition_from_public_transaction(&next, 2, 0)
        .unwrap();
    assert_eq!(stored_key(&state, sender.account_id()), key_at(&sender, 2));
}

#[test]
fn public_an_account_that_does_not_sign_keeps_its_key() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let mut state = V03State::new()
        .with_public_account_balances([(a.account_id(), 100), (b.account_id(), 100)]);
    state
        .transition_from_public_transaction(
            &native_transfer(&b, a.account_id(), Nonce(0), 10),
            1,
            0,
        )
        .unwrap();

    // Credited by a transfer it does not sign.
    state
        .transition_from_public_transaction(
            &native_transfer(&a, b.account_id(), Nonce(0), 30),
            2,
            0,
        )
        .unwrap();

    let account = state.get_account_by_id(b.account_id());
    assert_eq!(account.data.native_balance(), Ok(120));
    assert_eq!(account.nonce, Nonce(1));
    assert_eq!(
        account.data.actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&b, 1)
    );
}

#[test]
fn public_nonces_n_and_n_plus_one_of_one_account_apply_back_to_back() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let mut state =
        V03State::new().with_public_account_balances([(sender.account_id(), 100), (recipient, 0)]);

    for nonce in 0..3 {
        let diff = ValidatedStateDiff::from_public_transaction(
            &native_transfer(&sender, recipient, Nonce(nonce), 10),
            &state,
            1,
            0,
        )
        .unwrap();
        state.apply_state_diff(diff).unwrap();

        assert_eq!(
            state.get_account_by_id(sender.account_id()).nonce,
            Nonce(nonce + 1)
        );
        assert_eq!(
            stored_key(&state, sender.account_id()),
            key_at(&sender, nonce + 1)
        );
    }
    assert_eq!(
        state.get_account_by_id(recipient).data.native_balance(),
        Ok(30)
    );
}

#[test]
fn public_a_changed_byte_in_any_signers_next_key_breaks_every_signature() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = transfer_transaction(a.account_id(), &a, 0, b.account_id(), &b, 0, 30);
    let mut signers = [&a, &b];
    signers.sort_by_key(|signer| signer.account_id());

    for changed in 0..signers.len() {
        for byte in 0..32 {
            let mut tx = honest.clone();
            tx.witness_set.entries[changed].next.key_commitment[byte] ^= 1;
            let next: Vec<_> = tx
                .witness_set
                .entries
                .iter()
                .map(|entry| entry.next)
                .collect();
            let message_with_keys = tx.message.message_with_keys(&next);

            for (entry, signer) in tx.witness_set.entries.iter().zip(signers) {
                assert_eq!(
                    authenticate(
                        &signer.key_state(Nonce(0)),
                        &message_with_keys,
                        &entry.auth_data,
                        &entry.next
                    ),
                    Err(AuthError::InvalidSignature)
                );
            }
            assert_refused(
                ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0),
                signers[0].account_id(),
                "invalid signature",
            );
        }
    }
}

#[test]
fn public_a_signer_at_a_nonzero_nonce_without_a_stored_key_is_refused() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state = V03State::new().with_public_accounts([
        (
            sender.account_id(),
            Account {
                nonce: Nonce(1),
                ..Account::funded(100)
            },
        ),
        (recipient, Account::default()),
    ]);
    let tx = native_transfer(&sender, recipient, Nonce(1), 10);
    // Signed with the key the account id derives from, which the nonce-0 rule would accept.
    let mut with_initial_key = tx.clone();
    let message_with_keys = tx.message.message_with_keys(&[sender.key_state(Nonce(1))]);
    with_initial_key.witness_set.entries = vec![sender.entry(Nonce(0), &message_with_keys)];

    for signed in [with_initial_key, tx] {
        assert_refused(
            ValidatedStateDiff::from_public_transaction(&signed, &state, 1, 0),
            sender.account_id(),
            "no key is stored at nonce 1",
        );
    }
}

#[test]
fn public_a_signer_whose_account_the_transaction_also_writes_ends_with_its_new_key() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let mut state = V03State::new().with_public_accounts([
        (
            sender.account_id(),
            Account {
                nonce: Nonce(1),
                ..Account::funded(100)
            }
            .with_actor_state(SIGNATURE_PROGRAM_ID, key_at(&sender, 1)),
        ),
        (recipient, Account::default()),
    ]);

    let diff = ValidatedStateDiff::from_public_transaction(
        &native_transfer(&sender, recipient, Nonce(1), 10),
        &state,
        1,
        0,
    )
    .unwrap();
    // The debited sender's written account still carries the key it authenticated with.
    assert_eq!(
        diff.public_diff()[&sender.account_id()]
            .data
            .actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&sender, 1)
    );
    state.apply_state_diff(diff).unwrap();

    let account = state.get_account_by_id(sender.account_id());
    assert_eq!(account.data.native_balance(), Ok(90));
    assert_eq!(account.nonce, Nonce(2));
    assert_eq!(
        account.data.actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&sender, 2)
    );
}

#[test]
fn privacy_a_signer_at_nonce_zero_authenticates_with_the_key_giving_its_account_id() {
    let sender = TestSigner::new(51);
    let mut state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    let tx = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 30);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(state.get_account_by_id(sender.account_id()).nonce, Nonce(1));
    assert_eq!(stored_key(&state, sender.account_id()), key_at(&sender, 1));
}

#[test]
fn privacy_a_signer_at_nonce_zero_is_refused_a_key_not_giving_its_account_id() {
    let sender = TestSigner::new(51);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    let honest = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 30);

    // Another account's key, and the account's own key for a later nonce.
    for (holder, nonce) in [(TestSigner::new(53), 0), (sender.clone(), 1)] {
        let mut tx = honest.clone();
        let message_with_keys = tx
            .message
            .message_with_keys(&[holder.key_state(Nonce(nonce + 1))]);
        tx.witness_set.entries = vec![holder.entry(Nonce(nonce), &message_with_keys)];

        assert_refused(
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
            sender.account_id(),
            "revealed key does not give the account id",
        );
    }
}

#[test]
fn privacy_a_tampered_byte_in_any_signers_authentication_data_is_refused() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);
    assert!(ValidatedStateDiff::from_privacy_preserving_transaction(&honest, &state, 1, 0).is_ok());

    for (index, signer) in honest.signer_account_ids().into_iter().enumerate() {
        for position in 0..96 {
            let mut tx = honest.clone();
            tx.witness_set.entries[index].auth_data[position] ^= 1;
            let reason = tampered_reason(&tx.witness_set.entries[index].auth_data, position);

            assert_refused(
                ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
                signer,
                reason,
            );
        }
    }
}

#[test]
fn privacy_a_successful_transaction_rotates_every_signers_key_and_advances_its_nonce() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let mut state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let tx = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(
        state
            .get_account_by_id(a.account_id())
            .data
            .native_balance(),
        Ok(70)
    );
    for signer in [&a, &b] {
        let account = state.get_account_by_id(signer.account_id());
        assert_eq!(account.nonce, Nonce(1));
        assert_eq!(
            account.data.actor_state(SIGNATURE_PROGRAM_ID),
            &key_at(signer, 1)
        );
    }
}

#[test]
fn privacy_a_charged_revert_falls_back_to_the_fee_but_rotates_the_signers_key_and_advances_its_nonce()
 {
    let signer = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let payer = test_private_account_keys_1();
    let payer_account = Account::funded(100);
    let mut state = V03State::new()
        .with_public_account_balances([(signer.account_id(), 10), (recipient, 0), (FEE_INBOX, 0)])
        .with_private_account(&payer, &payer_account);
    // Proven as if the signer held the 11 it moves, so it fails only at settlement.
    let tx =
        privacy_transfer_paying_privately(&state, &signer, recipient, 11, &payer, &payer_account);

    let (diff, charge) = ValidatedStateDiff::from_privacy_preserving_transaction_metered(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect("a charged revert falls back to the fee");
    assert_eq!(
        charge.revert,
        Some(
            LeeError::from(InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::InsufficientBalance {
                    account_id: signer.account_id()
                }
            ))
            .to_string()
        )
    );
    state.apply_state_diff(diff).unwrap();

    let account = state.get_account_by_id(signer.account_id());
    assert_eq!(account.data.native_balance(), Ok(10));
    assert_eq!(account.nonce, Nonce(1));
    assert_eq!(
        account.data.actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&signer, 1)
    );
    assert_eq!(
        state.get_account_by_id(recipient).data.native_balance(),
        Ok(0)
    );
    assert_eq!(
        state.get_account_by_id(FEE_INBOX).data.native_balance(),
        Ok(FEE)
    );
}

#[test]
fn privacy_the_next_transaction_authenticates_with_the_new_key_and_the_old_key_is_refused() {
    let sender = TestSigner::new(51);
    let mut state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    let first = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 10);
    state
        .transition_from_privacy_preserving_transaction(&first, 1, 0)
        .unwrap();

    let next = privacy_shield(&state, &[&sender], &test_private_account_keys_2(), 10);
    let mut with_old_key = next.clone();
    let message_with_keys = next
        .message
        .message_with_keys(&[sender.key_state(Nonce(1))]);
    with_old_key.witness_set.entries = vec![sender.entry(Nonce(0), &message_with_keys)];
    assert_refused(
        ValidatedStateDiff::from_privacy_preserving_transaction(&with_old_key, &state, 2, 0),
        sender.account_id(),
        "invalid signature",
    );

    state
        .transition_from_privacy_preserving_transaction(&next, 2, 0)
        .unwrap();
    assert_eq!(stored_key(&state, sender.account_id()), key_at(&sender, 2));
}

#[test]
fn privacy_an_account_that_does_not_sign_keeps_its_key() {
    let signer = TestSigner::new(51);
    let bystander = TestSigner::new(52);
    let payer = test_private_account_keys_1();
    let payer_account = Account::funded(100);
    let mut state = V03State::new()
        .with_public_accounts([
            (signer.account_id(), Account::funded(100)),
            (
                bystander.account_id(),
                Account {
                    nonce: Nonce(1),
                    ..Account::funded(7)
                }
                .with_actor_state(SIGNATURE_PROGRAM_ID, key_at(&bystander, 1)),
            ),
            (FEE_INBOX, Account::default()),
        ])
        .with_private_account(&payer, &payer_account);
    // Credited by a transfer it does not sign.
    let tx = privacy_transfer_paying_privately(
        &state,
        &signer,
        bystander.account_id(),
        30,
        &payer,
        &payer_account,
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(stored_key(&state, signer.account_id()), key_at(&signer, 1));
    let account = state.get_account_by_id(bystander.account_id());
    assert_eq!(account.data.native_balance(), Ok(37));
    assert_eq!(account.nonce, Nonce(1));
    assert_eq!(
        account.data.actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&bystander, 1)
    );
}

#[test]
fn privacy_nonces_n_and_n_plus_one_of_one_account_apply_back_to_back() {
    let sender = TestSigner::new(51);
    let mut state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);

    for (nonce, recipient) in [
        (0, test_private_account_keys_1()),
        (1, test_private_account_keys_2()),
    ] {
        let tx = privacy_shield(&state, &[&sender], &recipient, 10);
        let diff =
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).unwrap();
        state.apply_state_diff(diff).unwrap();

        assert_eq!(
            state.get_account_by_id(sender.account_id()).nonce,
            Nonce(nonce + 1)
        );
        assert_eq!(
            stored_key(&state, sender.account_id()),
            key_at(&sender, nonce + 1)
        );
    }
    assert_eq!(
        state
            .get_account_by_id(sender.account_id())
            .data
            .native_balance(),
        Ok(80)
    );
}

#[test]
fn privacy_a_changed_byte_in_any_signers_next_key_breaks_every_signature() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);
    let mut signers = [&a, &b];
    signers.sort_by_key(|signer| signer.account_id());

    for changed in 0..signers.len() {
        for byte in 0..32 {
            let mut tx = honest.clone();
            tx.witness_set.entries[changed].next.key_commitment[byte] ^= 1;
            let next: Vec<_> = tx
                .witness_set
                .entries
                .iter()
                .map(|entry| entry.next)
                .collect();
            let message_with_keys = tx.message.message_with_keys(&next);

            for (entry, signer) in tx.witness_set.entries.iter().zip(signers) {
                assert_eq!(
                    authenticate(
                        &signer.key_state(Nonce(0)),
                        &message_with_keys,
                        &entry.auth_data,
                        &entry.next
                    ),
                    Err(AuthError::InvalidSignature)
                );
            }
            assert_refused(
                ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
                signers[0].account_id(),
                "invalid signature",
            );
        }
    }
}

#[test]
fn privacy_a_signer_at_a_nonzero_nonce_without_a_stored_key_is_refused() {
    let sender = TestSigner::new(51);
    let state = V03State::new().with_public_accounts([(
        sender.account_id(),
        Account {
            nonce: Nonce(1),
            ..Account::funded(100)
        },
    )]);
    let tx = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 10);
    // Signed with the key the account id derives from, which the nonce-0 rule would accept.
    let mut with_initial_key = tx.clone();
    let message_with_keys = tx.message.message_with_keys(&[sender.key_state(Nonce(1))]);
    with_initial_key.witness_set.entries = vec![sender.entry(Nonce(0), &message_with_keys)];

    for signed in [with_initial_key, tx] {
        assert_refused(
            ValidatedStateDiff::from_privacy_preserving_transaction(&signed, &state, 1, 0),
            sender.account_id(),
            "no key is stored at nonce 1",
        );
    }
}

#[test]
fn privacy_a_signer_whose_account_the_transaction_also_writes_ends_with_its_new_key() {
    let sender = TestSigner::new(51);
    let mut state = V03State::new().with_public_accounts([(
        sender.account_id(),
        Account {
            nonce: Nonce(1),
            ..Account::funded(100)
        }
        .with_actor_state(SIGNATURE_PROGRAM_ID, key_at(&sender, 1)),
    )]);
    let tx = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 10);

    let diff = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).unwrap();
    // The debited sender's written account still carries the key it authenticated with.
    assert_eq!(
        diff.public_diff()[&sender.account_id()]
            .data
            .actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&sender, 1)
    );
    state.apply_state_diff(diff).unwrap();

    let account = state.get_account_by_id(sender.account_id());
    assert_eq!(account.data.native_balance(), Ok(90));
    assert_eq!(account.nonce, Nonce(2));
    assert_eq!(
        account.data.actor_state(SIGNATURE_PROGRAM_ID),
        &key_at(&sender, 2)
    );
}
