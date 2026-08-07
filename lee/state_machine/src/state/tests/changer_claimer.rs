use super::*;

#[test]
fn public_changer_claimer_no_data_change_no_claim_succeeds() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::changer_claimer().id();
    // Don't change data (None) and don't claim (false)
    let instruction: (Option<Vec<u8>>, bool) = (None, false);

    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], instruction)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    // Should succeed - no changes made, no claim needed
    assert!(result.is_ok());
    // Account should remain default/unclaimed
    assert_eq!(state.get_account_by_id(account_id), Account::default());
}

#[test]
fn public_changer_claimer_data_change_no_claim_fails() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::changer_claimer().id();
    // Change data but don't claim (false) - should fail
    let new_data = vec![1, 2, 3, 4, 5];
    let instruction: (Option<Vec<u8>>, bool) = (Some(new_data), false);

    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], instruction)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    // Should fail - cannot modify data without claiming the account
    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::DefaultAccountModifiedWithoutClaim {
                account_id: err_account_id
            }
        )) if err_account_id == account_id
    ));
}

#[test]
fn private_changer_claimer_no_data_change_no_claim_succeeds() {
    let program = crate::test_methods::changer_claimer();
    let sender_keys = test_private_account_keys_1();
    let private_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    // Don't change data (None) and don't claim (false)
    let instruction: (Option<Vec<u8>>, bool) = (None, false);

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(instruction).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: sender_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular,
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: sender_keys.nsk,
                membership_proof: (0, vec![]),
            },
        })],
        &program.into(),
    );

    // Should succeed - no changes made, no claim needed
    assert!(result.is_ok());
}

#[test]
fn private_changer_claimer_data_change_no_claim_fails() {
    let program = crate::test_methods::changer_claimer();
    let sender_keys = test_private_account_keys_1();
    let private_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    // Change data but don't claim (false) - should fail
    let new_data = vec![1, 2, 3, 4, 5];
    let instruction: (Option<Vec<u8>>, bool) = (Some(new_data), false);

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(instruction).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: sender_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular,
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: sender_keys.nsk,
                membership_proof: (0, vec![]),
            },
        })],
        &program.into(),
    );

    // Should fail - cannot modify data without claiming the account
    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}
