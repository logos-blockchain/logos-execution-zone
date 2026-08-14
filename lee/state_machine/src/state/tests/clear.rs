use lee_core::program::{ClearValidationError, DEFAULT_PROGRAM_ID, SystemInstruction};

use super::*;

const HOSTILE_OWNER: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];

#[test]
fn clear_reclaims_hostile_owned_account() {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let mut state = V03State::new();
    state.force_insert_account(
        id,
        Account {
            program_owner: HOSTILE_OWNER,
            balance: 500,
            data: vec![0xca, 0xfe].try_into().unwrap(),
            nonce: Nonce(0),
        },
    );

    let message = public_transaction::Message::try_new(
        DEFAULT_PROGRAM_ID,
        vec![id],
        vec![Nonce(0)],
        SystemInstruction::Clear,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(id),
        Account {
            program_owner: DEFAULT_PROGRAM_ID,
            balance: 500,
            data: Data::default(),
            nonce: Nonce(1),
        }
    );
}

#[test]
fn clear_by_non_signer_is_rejected() {
    let victim_key = PrivateKey::try_new([1; 32]).unwrap();
    let victim = AccountId::from(&PublicKey::new_from_private_key(&victim_key));
    let attacker_key = PrivateKey::try_new([2; 32]).unwrap();

    let victim_account = Account {
        program_owner: HOSTILE_OWNER,
        balance: 500,
        data: vec![0xca, 0xfe].try_into().unwrap(),
        nonce: Nonce(0),
    };
    let mut state = V03State::new();
    state.force_insert_account(victim, victim_account.clone());

    let message = public_transaction::Message::try_new(
        DEFAULT_PROGRAM_ID,
        vec![victim],
        vec![Nonce(0)],
        SystemInstruction::Clear,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&attacker_key]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ClearValidationFailed(
                ClearValidationError::NotAuthorized { account_id }
            )
        )) if account_id == victim
    ));
    assert_eq!(state.get_account_by_id(victim), victim_account);
}

#[test]
fn clear_touches_only_the_named_account() {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let target = AccountId::from(&PublicKey::new_from_private_key(&key));
    let bystander = AccountId::new([9; 32]);
    let bystander_account = Account {
        program_owner: HOSTILE_OWNER,
        balance: 777,
        data: vec![0xaa].try_into().unwrap(),
        nonce: Nonce(3),
    };
    let mut state = V03State::new();
    state.force_insert_account(
        target,
        Account {
            program_owner: HOSTILE_OWNER,
            balance: 500,
            data: vec![0xca, 0xfe].try_into().unwrap(),
            nonce: Nonce(0),
        },
    );
    state.force_insert_account(bystander, bystander_account.clone());

    let message = public_transaction::Message::try_new(
        DEFAULT_PROGRAM_ID,
        vec![target],
        vec![Nonce(0)],
        SystemInstruction::Clear,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(target),
        Account {
            program_owner: DEFAULT_PROGRAM_ID,
            balance: 500,
            data: Data::default(),
            nonce: Nonce(1),
        }
    );
    assert_eq!(state.get_account_by_id(bystander), bystander_account);
}
