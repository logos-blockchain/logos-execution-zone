use lee_core::program::{
    ClearValidationError, DEFAULT_PROGRAM_ID, DEFAULT_PROGRAM_OWNER, SystemInstruction,
};

use super::*;

const HOSTILE_OWNER: AccountId = AccountId::new([1; 32]);

#[test]
fn clear_reassigns_to_the_declared_new_owner() {
    let key = PrivateKey::try_new([2; 32]).unwrap();
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let new_owner = AccountId::new([7; 32]);
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
        SystemInstruction::Clear { new_owner },
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(id),
        Account {
            program_owner: new_owner,
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
        SystemInstruction::Clear {
            new_owner: DEFAULT_PROGRAM_OWNER,
        },
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
        SystemInstruction::Clear {
            new_owner: DEFAULT_PROGRAM_OWNER,
        },
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(target),
        Account {
            program_owner: DEFAULT_PROGRAM_OWNER,
            balance: 500,
            data: Data::default(),
            nonce: Nonce(1),
        }
    );
    assert_eq!(state.get_account_by_id(bystander), bystander_account);
}

#[test]
fn clear_instruction_to_an_undeployed_program_is_rejected() {
    let key = PrivateKey::try_new([3; 32]).unwrap();
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let undeployed: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
    let account = Account {
        program_owner: HOSTILE_OWNER,
        balance: 500,
        data: vec![0xca, 0xfe].try_into().unwrap(),
        nonce: Nonce(0),
    };
    let mut state = V03State::new();
    state.force_insert_account(id, account.clone());

    let message = public_transaction::Message::try_new(
        undeployed,
        vec![id],
        vec![Nonce(0)],
        SystemInstruction::Clear {
            new_owner: DEFAULT_PROGRAM_OWNER,
        },
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(result, Err(LeeError::InvalidInput(_))));
    assert_eq!(state.get_account_by_id(id), account);
}

/// Reclaim is atomic in the useful sense: one `Clear { new_owner }` hands a hostile-owned account
/// to a program that can already spend its balance in the next transaction.
#[test]
fn reclaimed_account_is_spendable_under_its_new_owner() {
    let key = PrivateKey::try_new([4; 32]).unwrap();
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let recipient = AccountId::new([9; 32]);
    let transfer = crate::test_methods::modified_transfer_program();

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        id,
        Account {
            program_owner: HOSTILE_OWNER,
            balance: 500_000,
            data: vec![0xca, 0xfe].try_into().unwrap(),
            nonce: Nonce(0),
        },
    );

    let clear_message = public_transaction::Message::try_new(
        DEFAULT_PROGRAM_ID,
        vec![id],
        vec![Nonce(0)],
        SystemInstruction::Clear {
            new_owner: transfer.id().into(),
        },
    )
    .unwrap();
    let clear_witness_set = public_transaction::WitnessSet::for_message(&clear_message, &[&key]);
    let clear_tx = PublicTransaction::new(clear_message, clear_witness_set);

    state
        .transition_from_public_transaction(&clear_tx, 1, 0)
        .unwrap();

    let amount: u128 = 1;
    let transfer_message = public_transaction::Message::try_new(
        transfer.id(),
        vec![id, recipient],
        vec![Nonce(1)],
        amount,
    )
    .unwrap();
    let transfer_witness_set =
        public_transaction::WitnessSet::for_message(&transfer_message, &[&key]);
    let transfer_tx = PublicTransaction::new(transfer_message, transfer_witness_set);

    state
        .transition_from_public_transaction(&transfer_tx, 2, 0)
        .unwrap();

    let reclaimed = state.get_account_by_id(id);
    assert_eq!(reclaimed.program_owner, AccountId::from(transfer.id()));
    assert!(reclaimed.balance < 500_000);
    assert!(state.get_account_by_id(recipient).balance > 0);
}
