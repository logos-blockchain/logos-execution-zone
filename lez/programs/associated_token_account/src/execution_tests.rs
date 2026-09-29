#![cfg(test)]

use associated_token_account_core::ata_of;
use borsh::BorshSerialize;
use lee::{
    Account, AccountId, Actor, PrivateKey, PublicKey, PublicTransaction, ShardData, V03State,
    error::LeeError, public_transaction,
};
use lee_core::account::Nonce;
use token_core::{NewTokenDefinition, TokenDescriptor, TokenHolding, TokenKind};

fn token_program_id() -> AccountId {
    programs::token_account_id()
}

fn ata_program_id() -> AccountId {
    programs::ata_account_id()
}

fn owner_keys() -> (PrivateKey, AccountId) {
    let key = PrivateKey::try_new([9; 32]).unwrap();
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    (key, id)
}

fn public_tx<T: BorshSerialize>(
    to: Actor,
    public_actors: Vec<Actor>,
    nonces: Vec<Nonce>,
    message: T,
    signing_keys: &[&PrivateKey],
) -> PublicTransaction {
    let message = public_transaction::Message::try_new(to, public_actors, nonces, message).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, signing_keys);
    PublicTransaction::new(message, witness_set)
}

fn plant_definition(
    state: &mut V03State,
    block_id: u64,
    definition_id: AccountId,
    holding_id: AccountId,
    name: &str,
    total_supply: u128,
) {
    let definition = Actor::new(definition_id, token_program_id());
    let holding = Actor::new(holding_id, token_program_id());
    let tx = public_tx(
        definition,
        vec![definition, holding],
        vec![],
        token_core::Message::NewDefinition {
            definition: NewTokenDefinition::Fungible {
                name: name.to_string(),
                total_supply,
            },
            holding: holding_id,
            metadata: None,
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
    let (ata_id, _) = ata_of(
        ata_program_id(),
        owner_id,
        INTENDED_DEFINITION_ID,
        token_program_id(),
    );

    let noisy_ata = Account::funded(500).with_shard(FOREIGN_PROGRAM_ID, foreign_shard.clone());

    let mut state = V03State::new()
        .with_named_programs([
            (programs::token_account_id(), programs::token()),
            (programs::ata_account_id(), programs::ata()),
        ])
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

    let owner = Actor::new(owner_id, ata_program_id());
    let ata = Actor::new(ata_id, token_program_id());
    let create = |nonces, signing_keys: &[&PrivateKey]| {
        public_tx(
            owner,
            vec![
                owner,
                Actor::new(INTENDED_DEFINITION_ID, token_program_id()),
                ata,
            ],
            nonces,
            associated_token_account_core::Message::Create {
                token_program_id: token_program_id(),
                definition_id: INTENDED_DEFINITION_ID,
                kind: TokenKind::Fungible,
            },
            signing_keys,
        )
    };

    assert_rejected(
        &mut state,
        &create(vec![], &[]),
        3,
        "Only Uninitialized or authorized accounts can be initialized",
    );
    assert_rejected(
        &mut state,
        &public_tx(
            ata,
            vec![ata],
            vec![],
            token_core::Message::EnsureHolding {
                descriptor: TokenDescriptor {
                    definition_id: INTENDED_DEFINITION_ID,
                    kind: TokenKind::Fungible,
                },
            },
            &[],
        ),
        3,
        "Only Uninitialized or authorized accounts can be initialized",
    );

    let native_balance_before_repair = state
        .get_account_by_id(ata_id)
        .data
        .native_balance()
        .unwrap();
    let squatter_definition_before = state.get_account_by_id(SQUATTER_DEFINITION_ID);
    let intended_definition_before = state.get_account_by_id(INTENDED_DEFINITION_ID);

    let owner_nonce = state.get_account_by_id(owner_id).nonce;
    let repair_tx = create(vec![owner_nonce], &[&owner_key]);
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
    assert_eq!(
        repaired.data.native_balance().unwrap(),
        native_balance_before_repair
    );
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
