use super::*;

fn windowed_public_tx(script: Script) -> PublicTransaction {
    let actor = Actor::new(test_public_account_keys_1().account_id(), scripted_id());
    public_tx(actor, vec![actor], vec![], script, &[])
}

fn windowed_private_tx(script: &Script) -> PrivacyPreservingTransaction {
    let keys = test_private_account_keys_1();
    let account_id =
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO);
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(root(Actor::new(account_id, scripted_id()), script))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();
    private_tx(proven, vec![], &[])
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
fn validity_window_works_in_public_transactions(
    validity_window: (Option<BlockId>, Option<BlockId>),
    block_id: BlockId,
) {
    let block_validity_window: BlockValidityWindow = validity_window.try_into().unwrap();
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let tx = windowed_public_tx(Script {
        block_window: block_validity_window,
        ..Script::default()
    });
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
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let tx = windowed_public_tx(Script {
        timestamp_window: timestamp_validity_window,
        ..Script::default()
    });
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
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let tx = windowed_private_tx(&Script {
        block_window: block_validity_window,
        ..Script::default()
    });
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
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let tx = windowed_private_tx(&Script {
        timestamp_window: timestamp_validity_window,
        ..Script::default()
    });
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
