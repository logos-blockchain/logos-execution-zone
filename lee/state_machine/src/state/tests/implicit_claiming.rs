use super::*;

#[test]
fn public_echo_of_a_default_account_leaves_it_unowned() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::noop().id();

    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    // Writing nothing acquires nothing: the account stays unowned.
    assert!(result.is_ok());
    assert_eq!(state.get_account_by_id(account_id), Account::default());
}

#[test]
fn public_data_write_to_a_default_account_claims_it() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::data_changer().id();
    let new_data: Vec<u8> = vec![1, 2, 3, 4, 5];

    let message = public_transaction::Message::try_new(
        program_id,
        vec![account_id],
        vec![],
        new_data.clone(),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("writing data to an unowned account is how ownership is acquired");

    assert_eq!(
        state.get_account_by_id(account_id),
        Account {
            program_owner: program_id.into(),
            data: new_data.try_into().unwrap(),
            ..Account::default()
        }
    );
}

#[test]
fn private_echo_of_a_default_account_succeeds() {
    let program = crate::test_methods::noop();
    let sender_keys = test_private_account_keys_1();
    let private_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: sender_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(sender_keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: sender_keys.nsk(),
                membership_proof: (0, vec![]),
            },
        })],
        &program.into(),
    );

    assert!(result.is_ok());
}

#[test]
fn private_data_write_to_a_default_account_is_accepted() {
    let program = crate::test_methods::data_changer();
    let sender_keys = test_private_account_keys_1();
    let private_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let new_data: Vec<u8> = vec![1, 2, 3, 4, 5];

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(new_data).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: sender_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(sender_keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: sender_keys.nsk(),
                membership_proof: (0, vec![]),
            },
        })],
        &program.into(),
    );

    // The circuit applies the same implicit rule as the public path.
    assert!(result.is_ok());
}

#[test]
fn a_squatter_acquires_a_funded_account_but_still_cannot_spend_it() {
    let mut state = V03State::new().with_test_programs();
    let target_id = AccountId::new([1; 32]);
    let pocket_id = AccountId::new([2; 32]);
    let program_id = crate::test_methods::squatter().id();
    let data: Vec<u8> = vec![7; 8];

    // A funded address nobody has written to yet: reachable now that a credit
    // needs no claim, and the address a squatter goes after.
    state.force_insert_account(
        target_id,
        Account {
            balance: 100,
            ..Account::default()
        },
    );

    let squat = |data: Vec<u8>, amount: u128| {
        let message = public_transaction::Message::try_new(
            program_id,
            vec![target_id, pocket_id],
            vec![],
            (data, amount),
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        PublicTransaction::new(message, witness_set)
    };

    state
        .transition_from_public_transaction(&squat(data.clone(), 0), 1, 0)
        .expect("writing data to an unowned account is how ownership is acquired");
    assert_eq!(
        state.get_account_by_id(target_id),
        Account {
            program_owner: program_id.into(),
            balance: 100,
            data: data.clone().try_into().unwrap(),
            ..Account::default()
        },
        "the squatter owns the account and its balance is untouched"
    );

    // Owning it is not spending it: the balance moves only on the account's own
    // authorization, which a squatter can never supply.
    let result = state.transition_from_public_transaction(&squat(data, 50), 2, 0);
    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::UnauthorizedBalanceDecrease { account_id }
            )
        )) if account_id == target_id
    ));
    assert_eq!(state.get_account_by_id(target_id).balance, 100);
}

#[test]
fn a_credited_account_stays_unowned_and_its_key_can_spend_it() {
    let sender_key = PrivateKey::try_new([3; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let recipient_key = PrivateKey::try_new([4; 32]).unwrap();
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
    let onward_id = AccountId::new([5; 32]);
    let program_id = crate::test_methods::simple_balance_transfer().id();

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        sender_id,
        Account {
            balance: 100,
            ..Account::default()
        },
    );

    let message = public_transaction::Message::try_new(
        program_id,
        vec![sender_id, recipient_id],
        vec![Nonce(0)],
        40_u128,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sender_key]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 1, 0)
        .expect("crediting a fresh account requires no claim");

    let recipient = state.get_account_by_id(recipient_id);
    assert_eq!(recipient.balance, 40);
    assert_eq!(
        recipient.program_owner,
        Account::default().program_owner,
        "a credit leaves the recipient unowned"
    );

    // The credited balance is the key holder's to spend, with nothing owning the account.
    let message = public_transaction::Message::try_new(
        program_id,
        vec![recipient_id, onward_id],
        vec![Nonce(0)],
        10_u128,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&recipient_key]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 2, 0)
        .expect("an unowned account's own signature authorizes its debit");

    assert_eq!(state.get_account_by_id(recipient_id).balance, 30);
    assert_eq!(state.get_account_by_id(onward_id).balance, 10);
}

#[test]
fn an_unowned_signer_account_survives_its_nonce_advancing() {
    // Signing bumps the nonce, so an account that is never owned reaches a state
    // that used to be rejected on sight: not default, yet unowned.
    let sender_key = PrivateKey::try_new([6; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let recipient_id = AccountId::new([7; 32]);
    let program_id = crate::test_methods::simple_balance_transfer().id();

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        sender_id,
        Account {
            balance: 100,
            ..Account::default()
        },
    );

    for (block_id, nonce) in [(1, 0), (2, 1)] {
        let message = public_transaction::Message::try_new(
            program_id,
            vec![sender_id, recipient_id],
            vec![Nonce(nonce)],
            1_u128,
        )
        .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sender_key]);
        state
            .transition_from_public_transaction(
                &PublicTransaction::new(message, witness_set),
                block_id,
                0,
            )
            .expect("an unowned account stays usable once its nonce has advanced");
    }

    let sender = state.get_account_by_id(sender_id);
    assert_eq!(sender.balance, 98);
    assert_eq!(sender.nonce, Nonce(2));
    assert_eq!(sender.program_owner, Account::default().program_owner);
}

#[test]
fn an_unauthorized_private_data_write_acquires_the_account() {
    // Delivery to a foreign private account is the whole reason claiming had to
    // become permissionless: a sender never holds the recipient's `ask`, so the
    // write must acquire the account without it.
    let program = crate::test_methods::data_changer();
    let program_id = program.id();
    let recipient_keys = test_private_account_keys_1();
    let account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let private_account = AccountWithMetadata::new(Account::default(), false, account_id);
    let new_data: Vec<u8> = vec![1, 2, 3, 4, 5];

    let (output, _proof) = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(new_data.clone()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: recipient_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: recipient_keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .expect("writing to a private account needs no authorization from its owner");

    // The note the write produces is the account it acquired, owner and all.
    let expected = Commitment::new(
        &account_id,
        &Account {
            program_owner: program_id.into(),
            nonce: Nonce::private_account_nonce_init(&account_id),
            data: new_data.try_into().unwrap(),
            ..Account::default()
        },
    );
    assert!(output.commitments().contains(&expected));
}

#[test]
fn a_private_write_to_a_foreign_owned_account_is_rejected() {
    // Rule 6 is what stops acquisition from becoming seizure, and it must hold in
    // the circuit exactly as it does on the public path.
    let program = crate::test_methods::data_changer();
    let owner_id = crate::test_methods::noop().id();
    let sender_keys = test_private_account_keys_1();
    let owned = Account {
        program_owner: owner_id.into(),
        ..Account::default()
    };
    let private_account =
        AccountWithMetadata::new(owned, true, (&sender_keys.npk(), &sender_keys.vpk(), 0));

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(vec![9_u8; 4]).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: sender_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(sender_keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: sender_keys.nsk(),
                membership_proof: (0, vec![]),
            },
        })],
        &program.into(),
    );

    assert!(
        matches!(
            &result,
            Err(LeeError::CircuitProvingError(message))
                if message.contains("Unauthorized modification of data")
        ),
        "expected rule 6 to reject the write, got {:?}",
        result.as_ref().err()
    );
}

/// A private sender crediting a public unowned recipient: the recipient gains the balance and
/// stays unowned, exactly as on the public path.
#[test]
fn private_credit_to_a_public_unowned_recipient_leaves_it_unowned() {
    let program = crate::test_methods::simple_balance_transfer();
    let program_id = program.id();
    let sender_keys = test_private_account_keys_1();
    let sender_private_account = Account {
        program_owner: program_id.into(),
        balance: 100,
        ..Account::default()
    };
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let sender_init_nullifier = Nullifier::for_account_initialization(&sender_account_id);
    let mut state =
        V03State::new().with_private_accounts([(sender_commitment, sender_init_nullifier)]);
    let sender_pre = AccountWithMetadata::new(
        sender_private_account,
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let recipient_private_key = PrivateKey::try_new([2; 32]).unwrap();
    let recipient_account_id =
        AccountId::from(&PublicKey::new_from_private_key(&recipient_private_key));
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, recipient_account_id);

    let balance = 37;

    let (output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance).unwrap(),
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
                    membership_proof: state
                        .get_proof_for_commitment(&sender_commitment)
                        .expect("sender's commitment must be in state"),
                },
            }),
            InputAccountIdentity::Public,
        ],
        &program.into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![Nonce(0)], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[&recipient_private_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let nullifier = Nullifier::for_account_update(&sender_commitment, &sender_keys.nsk());
    assert!(state.private_state.1.contains(&nullifier));

    assert_eq!(
        state.get_account_by_id(recipient_account_id),
        Account {
            balance,
            nonce: Nonce(1),
            ..Account::default()
        }
    );
}

/// Acquisition lands after the frame, so a callee handed the account in the same
/// transaction meets it owned by the caller: rule 6 refuses the write.
#[test]
fn a_callee_cannot_write_an_account_the_caller_acquired_in_the_same_transaction() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let caller_id = crate::test_methods::acquire_and_forward().id();
    let callee_id = crate::test_methods::data_changer().id();
    let account_id = AccountId::new([1; 32]);
    let message = public_transaction::Message::try_new(
        caller_id,
        vec![account_id],
        vec![],
        (
            Some(vec![1_u8]),
            callee_id,
            Program::serialize_instruction(vec![2_u8]).unwrap(),
        ),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::UnauthorizedDataModification { account_id: err_account_id, executing_program_id }
        ))) if err_account_id == account_id && executing_program_id == callee_id
    ));
    assert_eq!(state.get_account_by_id(account_id), Account::default());
}

/// Naming an account acquires nothing, so a callee handed an account the caller only
/// echoed is the first to write it — and takes it.
#[test]
fn a_callee_acquires_an_account_the_caller_merely_echoed() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let caller_id = crate::test_methods::acquire_and_forward().id();
    let callee_id = crate::test_methods::data_changer().id();
    let account_id = AccountId::new([1; 32]);
    let message = public_transaction::Message::try_new(
        caller_id,
        vec![account_id],
        vec![],
        (
            None::<Vec<u8>>,
            callee_id,
            Program::serialize_instruction(vec![2_u8]).unwrap(),
        ),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("an echoed account is the callee's to take");

    let account = state.get_account_by_id(account_id);
    assert_eq!(account.program_owner, callee_id.into());
    assert_eq!(account.data, vec![2_u8].try_into().unwrap());
}
