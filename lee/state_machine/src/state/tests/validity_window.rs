use super::*;

#[test_case::test_case((Some(1), Some(3)), 3; "at upper bound")]
#[test_case::test_case((Some(1), Some(3)), 2; "inside range")]
#[test_case::test_case((Some(1), Some(3)), 0; "below range")]
#[test_case::test_case((Some(1), Some(3)), 1; "at lower bound")]
#[test_case::test_case((Some(1), Some(3)), 4; "above range")]
#[test_case::test_case((Some(1), None), 1; "lower bound only - at bound")]
#[test_case::test_case((Some(1), None), 10; "lower bound only - above")]
#[test_case::test_case((Some(1), None), 0; "lower bound only - below")]
#[test_case::test_case((None, Some(3)), 3; "upper bound only - at bound")]
#[test_case::test_case((None, Some(3)), 0; "upper bound only - below")]
#[test_case::test_case((None, Some(3)), 4; "upper bound only - above")]
#[test_case::test_case((None, None), 0; "no bounds - always valid")]
#[test_case::test_case((None, None), 100; "no bounds - always valid 2")]
fn validity_window_works_in_public_transactions(
    validity_window: (Option<BlockId>, Option<BlockId>),
    block_id: BlockId,
) {
    let block_validity_window: BlockValidityWindow = validity_window.try_into().unwrap();
    let validity_window_program = crate::test_methods::validity_window();
    let account_keys = test_public_account_keys_1();
    let pre = AccountWithMetadata::new(Account::default(), false, account_keys.account_id());
    let mut state = V03State::new().with_test_programs();
    let tx = {
        let account_ids = vec![pre.account_id];
        let nonces = vec![];
        let program_id = validity_window_program.id();
        let instruction = (
            block_validity_window,
            TimestampValidityWindow::new_unbounded(),
        );
        let message =
            public_transaction::Message::try_new(program_id, account_ids, nonces, instruction)
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        PublicTransaction::new(message, witness_set)
    };
    let result = state.transition_from_public_transaction(&tx, block_id, 0);
    let is_inside_validity_window =
        match (block_validity_window.start(), block_validity_window.end()) {
            (Some(s), Some(e)) => s <= block_id && block_id < e,
            (Some(s), None) => s <= block_id,
            (None, Some(e)) => block_id < e,
            (None, None) => true,
        };
    if is_inside_validity_window {
        assert!(result.is_ok());
    } else {
        assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
    }
}

#[test_case::test_case((Some(1), Some(3)), 3; "at upper bound")]
#[test_case::test_case((Some(1), Some(3)), 2; "inside range")]
#[test_case::test_case((Some(1), Some(3)), 0; "below range")]
#[test_case::test_case((Some(1), Some(3)), 1; "at lower bound")]
#[test_case::test_case((Some(1), Some(3)), 4; "above range")]
#[test_case::test_case((Some(1), None), 1; "lower bound only - at bound")]
#[test_case::test_case((Some(1), None), 10; "lower bound only - above")]
#[test_case::test_case((Some(1), None), 0; "lower bound only - below")]
#[test_case::test_case((None, Some(3)), 3; "upper bound only - at bound")]
#[test_case::test_case((None, Some(3)), 0; "upper bound only - below")]
#[test_case::test_case((None, Some(3)), 4; "upper bound only - above")]
#[test_case::test_case((None, None), 0; "no bounds - always valid")]
#[test_case::test_case((None, None), 100; "no bounds - always valid 2")]
fn timestamp_validity_window_works_in_public_transactions(
    validity_window: (Option<Timestamp>, Option<Timestamp>),
    timestamp: Timestamp,
) {
    let timestamp_validity_window: TimestampValidityWindow = validity_window.try_into().unwrap();
    let validity_window_program = crate::test_methods::validity_window();
    let account_keys = test_public_account_keys_1();
    let pre = AccountWithMetadata::new(Account::default(), false, account_keys.account_id());
    let mut state = V03State::new().with_test_programs();
    let tx = {
        let account_ids = vec![pre.account_id];
        let nonces = vec![];
        let program_id = validity_window_program.id();
        let instruction = (
            BlockValidityWindow::new_unbounded(),
            timestamp_validity_window,
        );
        let message =
            public_transaction::Message::try_new(program_id, account_ids, nonces, instruction)
                .unwrap();
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
        PublicTransaction::new(message, witness_set)
    };
    let result = state.transition_from_public_transaction(&tx, 1, timestamp);
    let is_inside_validity_window = match (
        timestamp_validity_window.start(),
        timestamp_validity_window.end(),
    ) {
        (Some(s), Some(e)) => s <= timestamp && timestamp < e,
        (Some(s), None) => s <= timestamp,
        (None, Some(e)) => timestamp < e,
        (None, None) => true,
    };
    if is_inside_validity_window {
        assert!(result.is_ok());
    } else {
        assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
    }
}

#[test_case::test_case((Some(1), Some(3)), 3; "at upper bound")]
#[test_case::test_case((Some(1), Some(3)), 2; "inside range")]
#[test_case::test_case((Some(1), Some(3)), 0; "below range")]
#[test_case::test_case((Some(1), Some(3)), 1; "at lower bound")]
#[test_case::test_case((Some(1), Some(3)), 4; "above range")]
#[test_case::test_case((Some(1), None), 1; "lower bound only - at bound")]
#[test_case::test_case((Some(1), None), 10; "lower bound only - above")]
#[test_case::test_case((Some(1), None), 0; "lower bound only - below")]
#[test_case::test_case((None, Some(3)), 3; "upper bound only - at bound")]
#[test_case::test_case((None, Some(3)), 0; "upper bound only - below")]
#[test_case::test_case((None, Some(3)), 4; "upper bound only - above")]
#[test_case::test_case((None, None), 0; "no bounds - always valid")]
#[test_case::test_case((None, None), 100; "no bounds - always valid 2")]
fn validity_window_works_in_privacy_preserving_transactions(
    validity_window: (Option<BlockId>, Option<BlockId>),
    block_id: BlockId,
) {
    let block_validity_window: BlockValidityWindow = validity_window.try_into().unwrap();
    let validity_window_program = crate::test_methods::validity_window();
    let account_keys = test_private_account_keys_1();
    let pre = AccountWithMetadata::new(
        Account::default(),
        false,
        (&account_keys.npk(), &account_keys.vpk(), 0),
    );
    let mut state = V03State::new().with_test_programs();
    let tx = {
        let instruction = (
            block_validity_window,
            TimestampValidityWindow::new_unbounded(),
        );
        let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
            vec![pre],
            Program::serialize_instruction(instruction).unwrap(),
            vec![InputAccountIdentity::PrivateForeignInit {
                vpk: account_keys.vpk(),
                random_seed: [0; 32],
                npk: account_keys.npk(),
                identifier: 0,
                commitment_root: DUMMY_COMMITMENT_HASH,
            }],
            &validity_window_program.into(),
        )
        .unwrap();

        let message = Message::try_from_circuit_output(vec![], vec![], output).unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]);
        PrivacyPreservingTransaction::new(message, witness_set)
    };
    let result = state.transition_from_privacy_preserving_transaction(&tx, block_id, 0);
    let is_inside_validity_window =
        match (block_validity_window.start(), block_validity_window.end()) {
            (Some(s), Some(e)) => s <= block_id && block_id < e,
            (Some(s), None) => s <= block_id,
            (None, Some(e)) => block_id < e,
            (None, None) => true,
        };
    if is_inside_validity_window {
        assert!(result.is_ok());
    } else {
        assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
    }
}

#[test_case::test_case((Some(1), Some(3)), 3; "at upper bound")]
#[test_case::test_case((Some(1), Some(3)), 2; "inside range")]
#[test_case::test_case((Some(1), Some(3)), 0; "below range")]
#[test_case::test_case((Some(1), Some(3)), 1; "at lower bound")]
#[test_case::test_case((Some(1), Some(3)), 4; "above range")]
#[test_case::test_case((Some(1), None), 1; "lower bound only - at bound")]
#[test_case::test_case((Some(1), None), 10; "lower bound only - above")]
#[test_case::test_case((Some(1), None), 0; "lower bound only - below")]
#[test_case::test_case((None, Some(3)), 3; "upper bound only - at bound")]
#[test_case::test_case((None, Some(3)), 0; "upper bound only - below")]
#[test_case::test_case((None, Some(3)), 4; "upper bound only - above")]
#[test_case::test_case((None, None), 0; "no bounds - always valid")]
#[test_case::test_case((None, None), 100; "no bounds - always valid 2")]
fn timestamp_validity_window_works_in_privacy_preserving_transactions(
    validity_window: (Option<Timestamp>, Option<Timestamp>),
    timestamp: Timestamp,
) {
    let timestamp_validity_window: TimestampValidityWindow = validity_window.try_into().unwrap();
    let validity_window_program = crate::test_methods::validity_window();
    let account_keys = test_private_account_keys_1();
    let pre = AccountWithMetadata::new(
        Account::default(),
        false,
        (&account_keys.npk(), &account_keys.vpk(), 0),
    );
    let mut state = V03State::new().with_test_programs();
    let tx = {
        let instruction = (
            BlockValidityWindow::new_unbounded(),
            timestamp_validity_window,
        );
        let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
            vec![pre],
            Program::serialize_instruction(instruction).unwrap(),
            vec![InputAccountIdentity::PrivateForeignInit {
                vpk: account_keys.vpk(),
                random_seed: [0; 32],
                npk: account_keys.npk(),
                identifier: 0,
                commitment_root: DUMMY_COMMITMENT_HASH,
            }],
            &validity_window_program.into(),
        )
        .unwrap();

        let message = Message::try_from_circuit_output(vec![], vec![], output).unwrap();

        let witness_set = WitnessSet::for_message(&message, proof, &[]);
        PrivacyPreservingTransaction::new(message, witness_set)
    };
    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, timestamp);
    let is_inside_validity_window = match (
        timestamp_validity_window.start(),
        timestamp_validity_window.end(),
    ) {
        (Some(s), Some(e)) => s <= timestamp && timestamp < e,
        (Some(s), None) => s <= timestamp,
        (None, Some(e)) => timestamp < e,
        (None, None) => true,
    };
    if is_inside_validity_window {
        assert!(result.is_ok());
    } else {
        assert!(matches!(result, Err(LeeError::OutOfValidityWindow)));
    }
}
