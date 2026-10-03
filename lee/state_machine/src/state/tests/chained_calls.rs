use super::*;

fn native_send(from: AccountId, to: AccountId, amount: u128) -> Call {
    Call::new(Actor::native_balance(from), &transfer(to, amount))
}

#[test]
fn public_sent_calls() {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&key));
    let to = AccountId::new([2; 32]);
    let initial_balance = 1000;
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance), (to, 0)])
        .with_programs([crate::test_methods::scripted()]);
    let amount: u128 = 37;

    // The scripted actor sends the transfer twice
    let expected_to_post = Account::funded(amount * 2);

    let sender = Actor::new(from, scripted_id());
    let tx = public_tx(
        sender,
        vec![
            sender,
            Actor::native_balance(from),
            Actor::native_balance(to),
        ],
        vec![Nonce(0)],
        Script::default()
            .send(native_send(from, to, amount))
            .send(native_send(from, to, amount)),
        &[&key],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let from_post = state.get_account_by_id(from);
    let to_post = state.get_account_by_id(to);
    assert_eq!(
        from_post.data.native_balance(),
        Ok(initial_balance - 2 * amount)
    );
    assert_eq!(to_post, expected_to_post);
}

fn self_sends(actor: Actor, depth: usize) -> Script {
    (0..depth).fold(Script::default(), |script, _| {
        Script::default().call(actor, &script)
    })
}

#[test]
fn a_long_self_send_chain_fits_the_public_budget() {
    let revisited = Actor::new(AccountId::new([1; 32]), scripted_id());
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let tx = public_tx(
        revisited,
        vec![revisited],
        vec![],
        self_sends(revisited, 64),
        &[],
    );

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("the root and 64 self-sends fit within the execution budget");
}

#[test]
fn execution_that_requires_authentication_of_a_program_derived_account_id_succeeds() {
    let pda_seed = PdaSeed::new([37; 32]);
    let from = AccountId::for_public_pda(&scripted_id(), &pda_seed);
    let to = AccountId::new([2; 32]);
    let initial_balance = 1000;
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance), (to, 0)])
        .with_programs([crate::test_methods::scripted()]);
    let amount: u128 = 58;

    let expected_to_post = Account::funded(amount);
    let delegator = Actor::new(from, scripted_id());
    let tx = public_tx(
        delegator,
        vec![
            delegator,
            Actor::native_balance(from),
            Actor::native_balance(to),
        ],
        vec![],
        Script::default().send(native_send(from, to, amount).with_pda_seeds(vec![pda_seed])),
        &[],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let from_post = state.get_account_by_id(from);
    let to_post = state.get_account_by_id(to);
    assert_eq!(
        from_post.data.native_balance(),
        Ok(initial_balance - amount)
    );
    assert_eq!(to_post, expected_to_post);
}

#[test]
fn a_pda_seed_delegated_to_one_sibling_does_not_leak_to_another() {
    let seed = PdaSeed::new([77; 32]);
    let pda_id = AccountId::for_public_pda(&scripted_id(), &seed);

    let mut state = V03State::new()
        .with_public_account_balances([(pda_id, 0)])
        .with_test_programs();

    // The first delivery carries the PDA's seed — real delegation. The sibling carries none, so
    // it sees `is_authorized == false` and its script panics on it.
    let delegator = Actor::new(pda_id, scripted_id());
    let callee = Actor::new(pda_id, TWIN);
    let tx = public_tx(
        delegator,
        vec![delegator, Actor::new(pda_id, TWIN)],
        vec![],
        Script::default()
            .send(Call::new(callee, &Script::default().authorized()).with_pda_seeds(vec![seed]))
            .call(callee, &Script::default().authorized()),
        &[],
    );

    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
        "a sibling handed the PDA but no pda_seeds must not see it as authorized, but got: \
         {result:?}"
    );
}

#[test]
fn a_credit_leaves_a_stranger_actor_state_at_the_recipient_untouched() {
    let from_key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let stranger = AccountId::new([9; 32]);
    let stranger_data: ActorState = b"stranger".to_vec().into();
    let initial_balance = 100;
    let amount: u128 = 37;
    let mut state = V03State::new()
        .with_public_accounts([
            (from, Account::funded(initial_balance)),
            (
                to,
                Account::default().with_actor_state(stranger, stranger_data.clone()),
            ),
        ])
        .with_programs([crate::test_methods::scripted()]);

    // The transaction runs the scripted actor, which sends to the native token program
    let sender = Actor::new(from, scripted_id());
    let tx = public_tx(
        sender,
        vec![
            sender,
            Actor::native_balance(from),
            Actor::native_balance(to),
        ],
        vec![Nonce(0), Nonce(0)],
        Script::default().send(native_send(from, to, amount)),
        &[&from_key, &to_key],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(from).data.native_balance(),
        Ok(initial_balance - amount)
    );
    assert_eq!(
        state.get_account_by_id(to),
        Account {
            nonce: Nonce(1),
            ..Account::funded(amount).with_actor_state(stranger, stranger_data)
        }
    );
}

#[test_case::test_case(1; "single call")]
#[test_case::test_case(2; "two calls")]
fn private_sent_calls(number_of_calls: u32) {
    // Arrange
    let from_keys = test_private_account_keys_1();
    let to_keys = test_private_account_keys_2();
    let initial_balance = 100;
    let from_pre = Account::funded(initial_balance);
    let to_pre = Account::default();

    let from_account_id = AccountId::for_regular_private_account(
        &from_keys.npk(),
        &from_keys.vpk(),
        Identifier::ZERO,
    );
    let to_account_id =
        AccountId::for_regular_private_account(&to_keys.npk(), &to_keys.vpk(), Identifier::ZERO);
    let from_commitment = Commitment::new(&from_account_id, &from_pre);
    let to_commitment = Commitment::new(&to_account_id, &to_pre);
    let from_init_nullifier = Nullifier::for_account_initialization(&from_account_id);
    let to_init_nullifier = Nullifier::for_account_initialization(&to_account_id);
    let mut state = V03State::new()
        .with_private_accounts([
            (from_commitment, from_init_nullifier),
            (to_commitment, to_init_nullifier),
        ])
        .with_programs([crate::test_methods::scripted()]);
    let amount: u128 = 37;
    let send = Call::new(
        Actor::native_balance(from_account_id),
        &transfer(to_account_id, amount),
    );
    let script =
        (0..number_of_calls).fold(Script::default(), |script, _| script.send(send.clone()));

    let from_new_nonce = Nonce::default().private_account_nonce_increment(&from_keys.nsk());
    let to_new_nonce = Nonce::default().private_account_nonce_increment(&to_keys.nsk());

    let from_expected_post = Account {
        nonce: from_new_nonce,
        ..Account::funded(initial_balance - u128::from(number_of_calls) * amount)
    };
    let from_expected_commitment = Commitment::new(&from_account_id, &from_expected_post);

    let to_expected_post = Account {
        nonce: to_new_nonce,
        ..Account::funded(u128::from(number_of_calls) * amount)
    };
    let to_expected_commitment = Commitment::new(&to_account_id, &to_expected_post);

    // Act
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![
                update_witness(
                    &from_keys,
                    Identifier::ZERO,
                    from_pre,
                    state
                        .get_proof_for_commitment(&from_commitment)
                        .expect("from's commitment must be in state"),
                ),
                update_witness(
                    &to_keys,
                    Identifier::ZERO,
                    to_pre,
                    state
                        .get_proof_for_commitment(&to_commitment)
                        .expect("to's commitment must be in state"),
                ),
            ],
            ..proving_input(root(Actor::new(from_account_id, scripted_id()), &script))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();

    let transaction = private_tx(proven, vec![], &[]);

    state
        .transition_from_privacy_preserving_transaction(&transaction, 1, 0)
        .unwrap();

    // Assert
    assert!(
        state
            .get_proof_for_commitment(&from_expected_commitment)
            .is_some()
    );
    assert!(
        state
            .get_proof_for_commitment(&to_expected_commitment)
            .is_some()
    );
}
