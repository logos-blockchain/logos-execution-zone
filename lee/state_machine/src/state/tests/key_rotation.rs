use lee_core::{
    FeeTransfer,
    signing_key::{SigningKeyState, signature_program_id},
};

use super::*;
use crate::{
    HeadAuthError, ValidatedStateDiff, authenticate_transaction_at_head,
    public_transaction::WitnessEntry,
    signature::{AuthError, authenticate, current_key},
};

const FEE: Balance = 5;
const FEE_INBOX: AccountId = AccountId::new([0xFE; 32]);

fn stored_key(state: &V03State, account_id: AccountId) -> ActorState {
    state
        .get_account_by_id(account_id)
        .data
        .actor_state(signature_program_id())
        .clone()
}

fn key_at(signer: &TestSigner, nonce: u128) -> ActorState {
    signer.key_state(Nonce(nonce)).encode()
}

fn assert_invalid<T>(result: Result<T, LeeError>, expected: &str) {
    match result {
        Err(LeeError::InvalidInput(message)) => assert_eq!(message, expected),
        Err(other) => panic!("expected `{expected}`, got {other:?}"),
        Ok(_) => panic!("expected `{expected}`, got a valid transaction"),
    }
}

fn assert_refused<T>(result: Result<T, LeeError>, signer: AccountId, reason: &str) {
    assert_invalid(
        result,
        &format!("Signer {signer} fails authentication: {reason}"),
    );
}

// An entry that cannot authenticate its signer on any head.
fn assert_malformed<T>(result: Result<T, LeeError>) {
    assert_invalid(result, &crate::InvalidTransaction::AuthData.to_string());
}

// What a signer at nonce 0 is refused with once its authentication data is changed at `position`:
// a changed initial key no longer gives the account id (or no longer decodes), and a changed
// public key may no longer decode, so the entry fits no head; otherwise the signature fails.
fn assert_tampered_refused<T>(
    result: Result<T, LeeError>,
    signer: AccountId,
    auth_data: &[u8],
    position: usize,
) {
    const INITIAL_KEY_LEN: usize = 33;
    let public_key_start = INITIAL_KEY_LEN + 64;
    let fits_no_head = position < INITIAL_KEY_LEN
        || (position >= public_key_start
            && crate::PublicKey::try_new(
                auth_data[public_key_start..]
                    .try_into()
                    .expect("a Schnorr entry ends with a 32-byte public key"),
            )
            .is_err());
    if fits_no_head {
        assert_malformed(result);
    } else {
        assert_refused(result, signer, "invalid signature");
    }
}

// `holder`'s entry at `nonce`, presented as a nonce-0 entry: a later key carries its own key
// state where the initial key goes.
fn entry_as_initial(
    holder: &TestSigner,
    nonce: Nonce,
    message_with_keys: &[u8; 32],
) -> WitnessEntry {
    let mut entry = holder.entry(nonce, message_with_keys);
    if nonce != Nonce(0) {
        entry.auth_data = [
            borsh::to_vec(&holder.key_state(nonce)).unwrap(),
            entry.auth_data,
        ]
        .concat();
    }
    entry
}

// `entry` without the initial key that prefixes a nonce-0 entry.
fn without_initial_key(signer: &TestSigner, mut entry: WitnessEntry) -> WitnessEntry {
    let (_, signature) = current_key(None, signer.account_id(), &entry.auth_data).unwrap();
    entry.auth_data = signature.to_vec();
    entry
}

// `key` with byte `byte` of its encoding changed: byte 0 is the key type, the rest the
// commitment. Byte 0 has no other value while Schnorr is the only key type.
fn with_changed_byte(mut key: SigningKeyState, byte: usize) -> SigningKeyState {
    assert_ne!(byte, 0, "there is no other key type to change to");
    key.key_commitment[byte - 1] ^= 1;
    key
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
                tip: 0,
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
    for (holder, nonce) in [(TestSigner::new(53), 0), (sender, 1)] {
        let mut tx = honest.clone();
        let message_with_keys = tx
            .message
            .message_with_keys(&[holder.key_state(Nonce(nonce + 1))]);
        tx.witness_set.entries = vec![entry_as_initial(&holder, Nonce(nonce), &message_with_keys)];

        assert_malformed(ValidatedStateDiff::from_public_transaction(
            &tx, &state, 1, 0,
        ));
    }
}

#[test]
fn public_a_tampered_byte_in_any_signers_authentication_data_is_refused() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = transfer_transaction(a.account_id(), &a, 0, b.account_id(), &b, 0, 30);
    assert!(ValidatedStateDiff::from_public_transaction(&honest, &state, 1, 0).is_ok());

    for (index, signer) in honest.signer_account_ids().into_iter().enumerate() {
        for position in 0..honest.witness_set.entries[index].auth_data.len() {
            let mut tx = honest.clone();
            tx.witness_set.entries[index].auth_data[position] ^= 1;
            assert_tampered_refused(
                ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0),
                signer,
                &tx.witness_set.entries[index].auth_data,
                position,
            );
        }
    }
}

#[test]
fn public_metered_a_tampered_witness_entry_is_refused_free_of_charge() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let mut tx = transfer_transaction(a.account_id(), &a, 0, b.account_id(), &b, 0, 30);
    let signer = tx.signer_account_ids()[0];
    let last = tx.witness_set.entries[0].auth_data.len() - 1;
    tx.witness_set.entries[0].auth_data[last] ^= 1;

    let (charge, result) = ValidatedStateDiff::from_public_transaction_metered(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    );
    assert_eq!(charge, crate::ExecutionCharge::FREE);
    assert_tampered_refused(result, signer, &tx.witness_set.entries[0].auth_data, last);
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
            account.data.actor_state(signature_program_id()),
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
            account.data.actor_state(signature_program_id()),
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
    with_old_key.witness_set.entries = vec![without_initial_key(
        &sender,
        sender.entry(Nonce(0), &message_with_keys),
    )];
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
        account.data.actor_state(signature_program_id()),
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
        for byte in 1..33 {
            let mut tx = honest.clone();
            tx.witness_set.entries[changed].next =
                with_changed_byte(tx.witness_set.entries[changed].next, byte);
            let next: Vec<_> = tx
                .witness_set
                .entries
                .iter()
                .map(|entry| entry.next)
                .collect();
            let message_with_keys = tx.message.message_with_keys(&next);

            for (entry, signer) in tx.witness_set.entries.iter().zip(signers) {
                assert_eq!(
                    current_key(None, signer.account_id(), &entry.auth_data).and_then(
                        |(current, signature)| authenticate(
                            &current,
                            &message_with_keys,
                            signature,
                            &entry.next
                        )
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
            .with_actor_state(signature_program_id(), key_at(&sender, 1)),
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
            .actor_state(signature_program_id()),
        &key_at(&sender, 1)
    );
    state.apply_state_diff(diff).unwrap();

    let account = state.get_account_by_id(sender.account_id());
    assert_eq!(account.data.native_balance(), Ok(90));
    assert_eq!(account.nonce, Nonce(2));
    assert_eq!(
        account.data.actor_state(signature_program_id()),
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
    for (holder, nonce) in [(TestSigner::new(53), 0), (sender, 1)] {
        let mut tx = honest.clone();
        let message_with_keys = tx
            .message
            .message_with_keys(&[holder.key_state(Nonce(nonce + 1))]);
        tx.witness_set.entries = vec![entry_as_initial(&holder, Nonce(nonce), &message_with_keys)];

        assert_malformed(ValidatedStateDiff::from_privacy_preserving_transaction(
            &tx, &state, 1, 0,
        ));
    }
}

#[test]
fn privacy_a_tampered_byte_in_any_signers_authentication_data_is_refused() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);
    assert!(ValidatedStateDiff::from_privacy_preserving_transaction(&honest, &state, 1, 0).is_ok());

    for (index, signer) in honest.signer_account_ids().into_iter().enumerate() {
        for position in 0..honest.witness_set.entries[index].auth_data.len() {
            let mut tx = honest.clone();
            tx.witness_set.entries[index].auth_data[position] ^= 1;
            assert_tampered_refused(
                ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
                signer,
                &tx.witness_set.entries[index].auth_data,
                position,
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
            account.data.actor_state(signature_program_id()),
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
        account.data.actor_state(signature_program_id()),
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
    with_old_key.witness_set.entries = vec![without_initial_key(
        &sender,
        sender.entry(Nonce(0), &message_with_keys),
    )];
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
                .with_actor_state(signature_program_id(), key_at(&bystander, 1)),
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
        account.data.actor_state(signature_program_id()),
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
        for byte in 1..33 {
            let mut tx = honest.clone();
            tx.witness_set.entries[changed].next =
                with_changed_byte(tx.witness_set.entries[changed].next, byte);
            let next: Vec<_> = tx
                .witness_set
                .entries
                .iter()
                .map(|entry| entry.next)
                .collect();
            let message_with_keys = tx.message.message_with_keys(&next);

            for (entry, signer) in tx.witness_set.entries.iter().zip(signers) {
                assert_eq!(
                    current_key(None, signer.account_id(), &entry.auth_data).and_then(
                        |(current, signature)| authenticate(
                            &current,
                            &message_with_keys,
                            signature,
                            &entry.next
                        )
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
        .with_actor_state(signature_program_id(), key_at(&sender, 1)),
    )]);
    let tx = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 10);

    let diff = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).unwrap();
    // The debited sender's written account still carries the key it authenticated with.
    assert_eq!(
        diff.public_diff()[&sender.account_id()]
            .data
            .actor_state(signature_program_id()),
        &key_at(&sender, 1)
    );
    state.apply_state_diff(diff).unwrap();

    let account = state.get_account_by_id(sender.account_id());
    assert_eq!(account.data.native_balance(), Ok(90));
    assert_eq!(account.nonce, Nonce(2));
    assert_eq!(
        account.data.actor_state(signature_program_id()),
        &key_at(&sender, 2)
    );
}

#[test]
fn privacy_witness_entries_must_follow_the_nonces_order() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let honest = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);
    assert!(ValidatedStateDiff::from_privacy_preserving_transaction(&honest, &state, 1, 0).is_ok());

    let mut tx = honest;
    tx.witness_set.entries.swap(0, 1);

    assert_malformed(ValidatedStateDiff::from_privacy_preserving_transaction(
        &tx, &state, 1, 0,
    ));
}

#[test]
fn privacy_a_witness_entry_of_an_unlisted_account_is_refused() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let mut tx = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);

    let stranger = TestSigner::new(53);
    let message_with_keys = tx
        .message
        .message_with_keys(&[stranger.key_state(Nonce(1)), tx.witness_set.entries[1].next]);
    tx.witness_set.entries[0] = stranger.entry(Nonce(0), &message_with_keys);

    assert_malformed(ValidatedStateDiff::from_privacy_preserving_transaction(
        &tx, &state, 1, 0,
    ));
}

#[test]
fn privacy_a_signer_without_a_witness_entry_is_refused() {
    let (a, b) = (TestSigner::new(51), TestSigner::new(52));
    let state = V03State::new().with_public_account_balances([(a.account_id(), 100)]);
    let tx = privacy_shield(&state, &[&a, &b], &test_private_account_keys_1(), 30);

    let (_, proof) = tx.witness_set.into_raw_parts();
    let witness_set = privacy_witness_for(&tx.message, proof, &[&a]);
    let tx = PrivacyPreservingTransaction::new(tx.message, witness_set);

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
        Err(LeeError::InvalidInput(msg)) if msg == crate::InvalidTransaction::Nonces.to_string()
    ));
}

// No pending transactions.
fn none_pending(_: AccountId, _: Nonce) -> Option<SigningKeyState> {
    None
}

// The refusal against the head inside a head authentication result.
fn at_head(result: Result<(), HeadAuthError>) -> Result<(), LeeError> {
    match result {
        Ok(()) => Ok(()),
        Err(HeadAuthError::AtHead(err)) => Err(err),
        Err(HeadAuthError::Definitive(err) | HeadAuthError::Pending(err)) => {
            panic!("expected a refusal against the head, got {err}")
        }
    }
}

#[test]
fn public_at_head_a_signer_at_its_accounts_nonce_is_authenticated() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let mut state =
        V03State::new().with_public_account_balances([(sender.account_id(), 100), (recipient, 0)]);
    let first = native_transfer(&sender, recipient, Nonce(0), 10);
    authenticate_transaction_at_head(&first, &state, none_pending).unwrap();

    let mut tampered = first.clone();
    // The signature's last byte: a Schnorr entry ends with the 32-byte public key.
    let in_signature = tampered.witness_set.entries[0].auth_data.len() - 33;
    tampered.witness_set.entries[0].auth_data[in_signature] ^= 1;
    assert_refused(
        at_head(authenticate_transaction_at_head(
            &tampered,
            &state,
            none_pending,
        )),
        sender.account_id(),
        "invalid signature",
    );

    // Once nonce 0 is used, a transaction at it is refused.
    state
        .transition_from_public_transaction(&first, 1, 0)
        .unwrap();
    assert!(matches!(
        at_head(authenticate_transaction_at_head(&first, &state, none_pending)),
        Err(LeeError::InvalidInput(message)) if message.contains("is below its account's nonce 1")
    ));
}

#[test]
fn public_at_head_a_malformed_transaction_is_refused_definitively() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    // No witness entry for its one signer: invalid whatever the head.
    let mut unsigned = native_transfer(&sender, recipient, Nonce(0), 10);
    unsigned.witness_set.entries.clear();

    assert!(matches!(
        authenticate_transaction_at_head(&unsigned, &state, none_pending),
        Err(HeadAuthError::Definitive(_))
    ));
}

#[test]
fn public_at_head_an_entry_fitting_no_head_is_refused_definitively() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    let honest = native_transfer(&sender, recipient, Nonce(0), 10);

    // Another account's initial key, and a length no key type has.
    let mut foreign_initial_key = honest.clone();
    foreign_initial_key.witness_set.entries[0].auth_data[..33]
        .copy_from_slice(&borsh::to_vec(&TestSigner::new(53).key_state(Nonce(0))).unwrap());
    let mut wrong_length = honest;
    wrong_length.witness_set.entries[0].auth_data.push(0);

    for tx in [foreign_initial_key, wrong_length] {
        assert!(matches!(
            authenticate_transaction_at_head(&tx, &state, none_pending),
            Err(HeadAuthError::Definitive(LeeError::InvalidInput(message)))
                if message == crate::InvalidTransaction::AuthData.to_string()
        ));
    }
}

#[test]
fn public_at_head_an_entry_fitting_another_head_is_refused_at_the_head() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    // Without its initial key, the entry fits a head that stores the sender's key, not this one.
    let mut tx = native_transfer(&sender, recipient, Nonce(0), 10);
    tx.witness_set.entries[0].auth_data.drain(..33);

    assert!(matches!(
        authenticate_transaction_at_head(&tx, &state, none_pending),
        Err(HeadAuthError::AtHead(_))
    ));
}

#[test]
fn public_at_head_a_signer_ahead_with_no_pending_transaction_is_refused() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);

    // Its key at nonce 1 depends on the transaction at nonce 0, which is not pending: even a
    // correctly signed transaction cannot be authenticated.
    let ahead = native_transfer(&sender, recipient, Nonce(1), 10);
    assert!(matches!(
        authenticate_transaction_at_head(&ahead, &state, none_pending),
        Err(HeadAuthError::Pending(LeeError::InvalidInput(message)))
            if message.contains("with no pending transaction before it")
    ));
}

#[test]
fn public_at_head_a_signer_ahead_is_checked_against_its_pending_key() {
    let sender = TestSigner::new(51);
    let recipient = AccountId::new([52; 32]);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    // The key the pending transaction at nonce 0 commits the account to at nonce 1.
    let pending_key = sender.key_state(Nonce(1));
    let pending = |account: AccountId, nonce: Nonce| {
        (account == sender.account_id() && nonce == Nonce(1)).then_some(pending_key)
    };

    let ahead = native_transfer(&sender, recipient, Nonce(1), 10);
    authenticate_transaction_at_head(&ahead, &state, pending).unwrap();

    let mut tampered = ahead;
    let last = tampered.witness_set.entries[0].auth_data.len() - 1;
    tampered.witness_set.entries[0].auth_data[last] ^= 1;
    assert!(matches!(
        authenticate_transaction_at_head(&tampered, &state, pending),
        Err(HeadAuthError::Pending(LeeError::InvalidInput(message)))
            if message.contains("fails authentication against its pending key")
    ));
}

#[test]
fn privacy_at_head_a_signer_at_its_accounts_nonce_is_authenticated() {
    let sender = TestSigner::new(51);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    let honest = privacy_shield(&state, &[&sender], &test_private_account_keys_1(), 30);
    authenticate_transaction_at_head(&honest, &state, none_pending).unwrap();

    let mut tampered = honest;
    // The signature's last byte: a Schnorr entry ends with the 32-byte public key.
    let in_signature = tampered.witness_set.entries[0].auth_data.len() - 33;
    tampered.witness_set.entries[0].auth_data[in_signature] ^= 1;
    assert_refused(
        at_head(authenticate_transaction_at_head(
            &tampered,
            &state,
            none_pending,
        )),
        sender.account_id(),
        "invalid signature",
    );
}

#[test]
fn privacy_at_head_a_signer_ahead_is_authenticated_only_on_top_of_a_pending_transaction() {
    let sender = TestSigner::new(51);
    let state = V03State::new().with_public_account_balances([(sender.account_id(), 100)]);
    // Signed at nonce 1, one ahead of the account's nonce 0.
    let at_nonce_1 = V03State::new().with_public_accounts([(
        sender.account_id(),
        Account {
            nonce: Nonce(1),
            ..Account::funded(100)
        },
    )]);
    let ahead = privacy_shield(&at_nonce_1, &[&sender], &test_private_account_keys_1(), 30);

    assert!(matches!(
        authenticate_transaction_at_head(&ahead, &state, none_pending),
        Err(HeadAuthError::Pending(LeeError::InvalidInput(message)))
            if message.contains("with no pending transaction before it")
    ));

    // The key the pending transaction at nonce 0 commits the account to at nonce 1.
    let pending_key = sender.key_state(Nonce(1));
    let pending = |account: AccountId, nonce: Nonce| {
        (account == sender.account_id() && nonce == Nonce(1)).then_some(pending_key)
    };
    authenticate_transaction_at_head(&ahead, &state, pending).unwrap();
}
