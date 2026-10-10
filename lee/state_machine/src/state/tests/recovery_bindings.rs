use lee_core::{EphemeralSecretKey, PrivateAccountKind, Recipient, RecipientEncryption};

use super::*;
use crate::ValidatedStateDiff;

fn recipient(opening: [u8; 32]) -> Recipient {
    let keys = test_private_account_keys_1();
    Recipient {
        npk: keys.npk(),
        vpk: keys.vpk(),
        kind: PrivateAccountKind::Regular,
        opening: Some(opening),
    }
}

fn recovery(opening: [u8; 32], esk: u8) -> RecipientEncryption {
    RecipientEncryption {
        recipient: recipient(opening),
        esk: EphemeralSecretKey([esk; 32]),
    }
}

#[test]
fn a_binding_proved_without_any_private_account_is_kept_for_its_recipient() {
    let mut state = V03State::new().with_test_programs();
    let input = recovery([7; 32], 5);
    let tx = binding(&Script::default(), vec![input.clone()]);
    let instance = &tx.message().execution;
    let [bound] = instance.recovery_bindings.as_slice() else {
        panic!("the proof binds exactly one address");
    };

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let keys = test_private_account_keys_1();
    assert!(instance.private_actions.is_empty());
    assert_eq!(bound, &input.bind_recovery());
    assert_eq!(bound.address, recipient([7; 32]).address());
    assert_eq!(
        Recipient::recover(bound.address, &bound.note, &keys.d, &keys.z),
        Some(recipient([7; 32]))
    );
    assert_eq!(state.recovery_binding(bound.address), Some(&bound.note));
}

#[test]
fn an_address_is_bound_at_most_once() {
    let mut state = V03State::new().with_test_programs();
    let first = binding(&Script::default(), vec![recovery([7; 32], 5)]);
    let again = binding(&Script::default(), vec![recovery([7; 32], 6)]);
    let twice = binding(
        &Script::default(),
        vec![recovery([8; 32], 5), recovery([8; 32], 6)],
    );
    let validated_before_the_first =
        ValidatedStateDiff::from_privacy_preserving_transaction(&again, &state, 1, 0).unwrap();
    state
        .transition_from_privacy_preserving_transaction(&first, 1, 0)
        .unwrap();
    let before = state.clone();

    for tx in [&first, &again, &twice] {
        assert!(matches!(
            state.transition_from_privacy_preserving_transaction(tx, 2, 0),
            Err(LeeError::InvalidInput(message)) if message.starts_with("A recovery binding for ")
        ));
    }
    assert!(matches!(
        state.apply_state_diff(validated_before_the_first),
        Err(LeeError::InvalidInput(message)) if message.starts_with("A recovery binding for ")
    ));
    assert_eq!(state, before);
}

#[test]
fn a_proof_with_neither_private_actions_nor_bindings_is_refused() {
    let mut state = V03State::new().with_test_programs();

    let result = state.transition_from_privacy_preserving_transaction(
        &binding(&Script::default(), Vec::new()),
        1,
        0,
    );

    assert!(matches!(
        result,
        Err(LeeError::InvalidInput(message))
            if message == "Empty commitments, nullifiers and recovery bindings found in message"
    ));
}
