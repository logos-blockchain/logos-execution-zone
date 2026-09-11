#![cfg(test)]

use associated_token_account_core::{compute_ata_seed, get_associated_token_account_id};
use lee_core::account::{AccountId, AccountInput, ProgramShardSelector, ShardData};
use token_core::{TokenDefinition, TokenHolding};

const ATA_PROGRAM_ID: AccountId = AccountId::new([1u8; 32]);
const TOKEN_PROGRAM_ID: AccountId = AccountId::new([2u8; 32]);

fn owner_id() -> AccountId {
    AccountId::new([0x01u8; 32])
}

fn definition_id() -> AccountId {
    AccountId::new([0x02u8; 32])
}

fn ata_of(definition_id: AccountId) -> AccountId {
    get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id, TOKEN_PROGRAM_ID),
    )
}

fn ata_id() -> AccountId {
    ata_of(definition_id())
}

fn token_input(account_id: AccountId, shard: ShardData) -> AccountInput {
    AccountInput::with_shard(account_id, false, 0, TOKEN_PROGRAM_ID, shard)
}

fn owner_account() -> AccountInput {
    AccountInput::balance_only(owner_id(), true, 0)
}

fn unauthorized_owner_account() -> AccountInput {
    AccountInput::balance_only(owner_id(), false, 0)
}

fn definition_account() -> AccountInput {
    token_input(
        definition_id(),
        ShardData::from(&TokenDefinition::Fungible {
            name: "TEST".to_string(),
            total_supply: 1000,
            metadata_id: None,
        }),
    )
}

fn matching_holding() -> ShardData {
    ShardData::from(&TokenHolding::Fungible {
        definition_id: definition_id(),
        balance: 100,
    })
}

fn foreign_holding() -> ShardData {
    ShardData::from(&TokenHolding::Fungible {
        definition_id: AccountId::new([0x99u8; 32]),
        balance: 100,
    })
}

#[test]
fn create_emits_chained_call_for_uninitialized_ata() {
    let (post_diffs, chained_calls) = crate::create::create_associated_token_account(
        unauthorized_owner_account(),
        definition_account(),
        token_input(ata_id(), ShardData::empty()),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    assert_eq!(post_diffs.len(), 3);
    assert_eq!(chained_calls.len(), 1);
    assert_eq!(chained_calls[0].program_account_id, TOKEN_PROGRAM_ID);
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_panics_on_wrong_ata_address() {
    crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        token_input(AccountId::new([0xFFu8; 32]), ShardData::empty()),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn get_associated_token_account_id_is_deterministic() {
    let seed = compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID);
    let id1 = get_associated_token_account_id(&ATA_PROGRAM_ID, &seed);
    let id2 = get_associated_token_account_id(&ATA_PROGRAM_ID, &seed);
    assert_eq!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_owner() {
    let other_owner = AccountId::new([0x99u8; 32]);
    let id1 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
    );
    let id2 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(other_owner, definition_id(), TOKEN_PROGRAM_ID),
    );
    assert_ne!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_definition() {
    let other_def = AccountId::new([0x99u8; 32]);
    let id1 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
    );
    let id2 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), other_def, TOKEN_PROGRAM_ID),
    );
    assert_ne!(id1, id2);
}

#[test]
fn the_ata_of_a_stranger_program_is_a_different_address() {
    let stranger = AccountId::new([0xEEu8; 32]);
    assert_ne!(
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
        ),
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), stranger),
        ),
        "each token program must get its own ATA family"
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_naming_a_stranger_program_cannot_reach_the_real_ata() {
    let stranger = AccountId::new([0xEEu8; 32]);
    crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        AccountInput::with_shard(ata_id(), false, 0, stranger, ShardData::empty()),
        ATA_PROGRAM_ID,
        stranger,
    );
}

#[test]
fn create_leaves_a_matching_holding_untouched_however_the_owner_is_authorized() {
    const NFT_DEFINITION_ID: AccountId = AccountId::new([0x03u8; 32]);
    let nft_definition = token_input(
        NFT_DEFINITION_ID,
        ShardData::from(&TokenDefinition::NonFungible {
            name: "NFT".to_string(),
            printable_supply: 5,
            metadata_id: AccountId::new([0u8; 32]),
        }),
    );
    let matches = [
        (definition_account(), matching_holding()),
        (
            nft_definition.clone(),
            ShardData::from(&TokenHolding::NftMaster {
                definition_id: NFT_DEFINITION_ID,
                print_balance: 5,
            }),
        ),
        (
            nft_definition,
            ShardData::from(&TokenHolding::NftPrintedCopy {
                definition_id: NFT_DEFINITION_ID,
                owned: true,
            }),
        ),
    ];

    for (definition, holding) in matches {
        for owner in [owner_account(), unauthorized_owner_account()] {
            let ata = token_input(ata_of(definition.account_id), holding.clone());
            let (post_diffs, chained_calls) = crate::create::create_associated_token_account(
                owner,
                definition.clone(),
                ata,
                ATA_PROGRAM_ID,
                TOKEN_PROGRAM_ID,
            );
            assert_eq!(post_diffs.len(), 3);
            assert!(chained_calls.is_empty());
        }
    }
}

#[test]
fn create_repairs_a_squatted_ata_and_delegates_the_seed() {
    let expected_seed = compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID);
    let expected_selectors = vec![
        ProgramShardSelector::new(definition_id(), TOKEN_PROGRAM_ID),
        ProgramShardSelector::new(ata_id(), TOKEN_PROGRAM_ID),
    ];
    let squats = [
        foreign_holding(),
        ShardData::from(&TokenHolding::NftMaster {
            definition_id: definition_id(),
            print_balance: 5,
        }),
        ShardData::try_from(vec![0xFFu8; 4]).unwrap(),
    ];

    for shard in squats {
        let (post_diffs, chained_calls) = crate::create::create_associated_token_account(
            owner_account(),
            definition_account(),
            token_input(ata_id(), shard),
            ATA_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
        );
        assert_eq!(post_diffs.len(), 3);
        let [call] = <[_; 1]>::try_from(chained_calls).unwrap();
        assert_eq!(call.program_account_id, TOKEN_PROGRAM_ID);
        assert_eq!(call.pda_seeds, vec![expected_seed]);
        assert_eq!(call.shard_selectors, expected_selectors);
        let decoded: token_core::Instruction = borsh::from_slice(&call.instruction_data).unwrap();
        assert!(matches!(
            decoded,
            token_core::Instruction::InitializeAccount
        ));
    }
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn create_rejects_unauthorized_repair() {
    crate::create::create_associated_token_account(
        unauthorized_owner_account(),
        definition_account(),
        AccountInput::with_shard(ata_id(), true, 0, TOKEN_PROGRAM_ID, foreign_holding()),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_panics_on_wrong_address_even_over_a_matching_shard() {
    crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        token_input(AccountId::new([0xABu8; 32]), matching_holding()),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );
}
