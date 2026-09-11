#![cfg(test)]

use associated_token_account_core::{compute_ata_seed, get_associated_token_account_id};
use borsh::BorshSerialize;
use lee::{
    Account, AccountData, AccountId, PrivateKey, ProgramShardSelector, PublicKey,
    PublicTransaction, ShardData, V03State, error::LeeError, public_transaction,
};
use lee_core::account::Nonce;
use token_core::TokenHolding;

fn token_program_id() -> AccountId {
    programs::token().id().into()
}

fn ata_program_id() -> AccountId {
    programs::ata().id().into()
}

fn owner_keys() -> (PrivateKey, AccountId) {
    let key = PrivateKey::try_new([9; 32]).unwrap();
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    (key, id)
}

fn public_tx<T: BorshSerialize>(
    program_id: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    nonces: Vec<Nonce>,
    instruction: T,
    signing_keys: &[&PrivateKey],
) -> PublicTransaction {
    let message =
        public_transaction::Message::try_new(program_id, shard_selectors, nonces, instruction)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, signing_keys);
    PublicTransaction::new(message, witness_set)
}

fn create_tx(
    shard_selectors: Vec<ProgramShardSelector>,
    nonces: Vec<Nonce>,
    signing_keys: &[&PrivateKey],
) -> PublicTransaction {
    public_tx(
        ata_program_id(),
        shard_selectors,
        nonces,
        associated_token_account_core::Instruction::Create {
            token_program_id: token_program_id(),
        },
        signing_keys,
    )
}

fn plant_definition(
    state: &mut V03State,
    block_id: u64,
    definition_id: AccountId,
    holding_id: AccountId,
    name: &str,
    total_supply: u128,
) {
    let tx = public_tx(
        token_program_id(),
        vec![
            ProgramShardSelector::new(definition_id, token_program_id()),
            ProgramShardSelector::new(holding_id, token_program_id()),
        ],
        vec![],
        token_core::Instruction::NewFungibleDefinition {
            name: name.to_string(),
            total_supply,
        },
        &[],
    );
    state
        .transition_from_public_transaction(&tx, block_id, 0)
        .unwrap();
}

fn assert_rejected(state: &mut V03State, tx: &PublicTransaction, block_id: u64, expected: &str) {
    let result = state.transition_from_public_transaction(tx, block_id, 0);
    assert!(
        matches!(&result, Err(LeeError::ProgramExecutionFailed(msg)) if msg.contains(expected)),
        "expected a rejection containing {expected:?}, got: {result:?}"
    );
}

#[test]
fn repairing_a_squat_requires_the_owner_and_disturbs_nothing_else() {
    const INTENDED_DEFINITION_ID: AccountId = AccountId::new([0x10; 32]);
    const SQUATTER_DEFINITION_ID: AccountId = AccountId::new([0x11; 32]);
    const THROWAWAY_HOLDING_ID: AccountId = AccountId::new([0x12; 32]);
    const FOREIGN_PROGRAM_ID: AccountId = AccountId::new([0x13; 32]);
    let foreign_shard = ShardData::try_from(vec![7u8; 4]).unwrap();

    let (owner_key, owner_id) = owner_keys();
    let ata_id = get_associated_token_account_id(
        &ata_program_id(),
        &compute_ata_seed(owner_id, INTENDED_DEFINITION_ID, token_program_id()),
    );

    let noisy_ata = Account {
        data: AccountData {
            balance: 500,
            ..AccountData::default()
        },
        ..Account::default()
    }
    .with_shard(FOREIGN_PROGRAM_ID, foreign_shard.clone());

    let mut state = V03State::new()
        .with_programs([programs::token(), programs::ata()])
        .with_public_accounts([(ata_id, noisy_ata)])
        .with_public_account_balances([(owner_id, 100)]);

    plant_definition(
        &mut state,
        1,
        INTENDED_DEFINITION_ID,
        THROWAWAY_HOLDING_ID,
        "INTENDED",
        1_000,
    );
    plant_definition(&mut state, 2, SQUATTER_DEFINITION_ID, ata_id, "SQUAT", 500);

    let definition_selector = ProgramShardSelector::new(INTENDED_DEFINITION_ID, token_program_id());
    let ata_selector = ProgramShardSelector::new(ata_id, token_program_id());
    let repair_selectors = vec![
        ProgramShardSelector::balance(owner_id),
        definition_selector,
        ata_selector,
    ];

    assert_rejected(
        &mut state,
        &create_tx(repair_selectors.clone(), vec![], &[]),
        3,
        "Owner authorization is missing",
    );
    assert_rejected(
        &mut state,
        &public_tx(
            token_program_id(),
            vec![definition_selector, ata_selector],
            vec![],
            token_core::Instruction::InitializeAccount,
            &[],
        ),
        3,
        "Only Uninitialized or authorized accounts can be initialized",
    );

    let native_balance_before_repair = state.get_account_by_id(ata_id).data.balance;
    let squatter_definition_before = state.get_account_by_id(SQUATTER_DEFINITION_ID);
    let intended_definition_before = state.get_account_by_id(INTENDED_DEFINITION_ID);

    let owner_nonce = state.get_account_by_id(owner_id).nonce;
    let repair_tx = create_tx(repair_selectors, vec![owner_nonce], &[&owner_key]);
    state
        .transition_from_public_transaction(&repair_tx, 3, 0)
        .unwrap();

    let repaired = state.get_account_by_id(ata_id);
    assert_eq!(
        TokenHolding::try_from(repaired.data.shard(token_program_id())).unwrap(),
        TokenHolding::Fungible {
            definition_id: INTENDED_DEFINITION_ID,
            balance: 0,
        }
    );
    assert_eq!(repaired.data.balance, native_balance_before_repair);
    assert_eq!(repaired.data.shard(FOREIGN_PROGRAM_ID), &foreign_shard);
    assert_eq!(
        state.get_account_by_id(SQUATTER_DEFINITION_ID),
        squatter_definition_before
    );
    assert_eq!(
        state.get_account_by_id(INTENDED_DEFINITION_ID),
        intended_definition_before
    );
}
