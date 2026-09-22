use super::*;

/// Mirror of the guest's instruction, for host-side serialisation.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum RobinhoodInstruction {
    Rebalance {
        balance_a: u128,
        balance_b: u128,
        amount: u128,
    },
}

struct Setup {
    state: V03State,
    program: Program,
    account_a: AccountId,
    account_b: AccountId,
}

fn setup(balance_a: u128, balance_b: u128) -> Setup {
    let program = crate::test_methods::robinhood();
    let account_a =
        AccountId::for_public_pda(&AccountId::from(program.id()), &PdaSeed::new([0; 32]));
    let account_b =
        AccountId::for_public_pda(&AccountId::from(program.id()), &PdaSeed::new([1; 32]));

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(account_a, Account::funded(balance_a));
    state.force_insert_account(account_b, Account::funded(balance_b));

    Setup {
        state,
        program,
        account_a,
        account_b,
    }
}

fn build_tx(setup: &Setup, instruction: RobinhoodInstruction) -> PublicTransaction {
    let message = public_transaction::Message::try_new(
        setup.program.id().into(),
        vec![
            ProgramShardSelector::balance(setup.account_a),
            ProgramShardSelector::balance(setup.account_b),
        ],
        vec![], // no signers, both accounts are PDA-authorised
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

#[test]
fn robinhood_routes_from_richer_to_poorer() {
    let setup = setup(100, 40);
    let tx = build_tx(
        &setup,
        RobinhoodInstruction::Rebalance {
            balance_a: 100,
            balance_b: 40,
            amount: 1,
        },
    );

    let mut state = setup.state;
    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(result.is_ok(), "robinhood should succeed: {result:?}");

    assert_eq!(state.get_account_by_id(setup.account_a).data.balance(), Ok(99));
    assert_eq!(state.get_account_by_id(setup.account_b).data.balance(), Ok(41));
}

#[test]
fn robinhood_routes_the_other_way_when_the_ordering_flips() {
    let setup = setup(40, 100);
    let tx = build_tx(
        &setup,
        RobinhoodInstruction::Rebalance {
            balance_a: 40,
            balance_b: 100,
            amount: 1,
        },
    );

    let mut state = setup.state;
    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(result.is_ok(), "robinhood should succeed: {result:?}");

    // The plan branched on the balances rather than hardcoding a direction.
    assert_eq!(state.get_account_by_id(setup.account_a).data.balance(), Ok(41));
    assert_eq!(state.get_account_by_id(setup.account_b).data.balance(), Ok(99));
}

#[test]
fn robinhood_aborts_when_a_proposed_balance_is_stale() {
    let setup = setup(100, 40);
    // The routing decision the caller wants, priced against a balance the chain does not hold.
    let tx = build_tx(
        &setup,
        RobinhoodInstruction::Rebalance {
            balance_a: 100,
            balance_b: 39,
            amount: 1,
        },
    );

    let mut state = setup.state;
    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        result.is_err(),
        "a proposal the guard cannot pin must abort: {result:?}"
    );

    assert_eq!(state.get_account_by_id(setup.account_a).data.balance(), Ok(100));
    assert_eq!(state.get_account_by_id(setup.account_b).data.balance(), Ok(40));
}

#[test]
fn robinhood_cannot_be_tricked_into_robbing_the_poor() {
    // Account A is the poorer one. The caller proposes the opposite ordering, which without the
    // guards would route the transfer out of A and into B.
    let setup = setup(40, 100);
    let tx = build_tx(
        &setup,
        RobinhoodInstruction::Rebalance {
            balance_a: 100,
            balance_b: 40,
            amount: 1,
        },
    );

    let mut state = setup.state;
    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        result.is_err(),
        "a proposal that inverts the real ordering must abort: {result:?}"
    );

    assert_eq!(state.get_account_by_id(setup.account_a).data.balance(), Ok(40));
    assert_eq!(state.get_account_by_id(setup.account_b).data.balance(), Ok(100));
}
