use super::*;

fn native_send(from: AccountId, to: AccountId, amount: u128) -> Envelope {
    Envelope::new(Actor::native_balance(from), &transfer(to, amount))
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
            .send(Envelope::new(callee, &Script::default().authorized()).with_pda_seeds(vec![seed]))
            .send(Envelope::new(callee, &Script::default().authorized())),
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
fn a_credit_leaves_a_stranger_shard_at_the_recipient_untouched() {
    let from_key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let stranger = AccountId::new([9; 32]);
    let stranger_data: ShardData = b"stranger".to_vec().try_into().unwrap();
    let initial_balance = 100;
    let amount: u128 = 37;
    let mut state = V03State::new()
        .with_public_accounts([
            (from, Account::funded(initial_balance)),
            (
                to,
                Account::default().with_shard(stranger, stranger_data.clone()),
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
            ..Account::funded(amount).with_shard(stranger, stranger_data)
        }
    );
}
