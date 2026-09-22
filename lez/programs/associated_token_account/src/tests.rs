#![cfg(test)]

use associated_token_account_core::{
    AtaContents, Instruction, compute_ata_seed, get_associated_token_account_id,
};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, Plan, ProgramInput, ResolveInput, ShardEffect},
};
use token_core::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind};

use crate::Effect;

const ATA_PROGRAM_ID: AccountId = AccountId::new([1u8; 32]);
const TOKEN_PROGRAM_ID: AccountId = AccountId::new([2u8; 32]);
const STRANGER_PROGRAM_ID: AccountId = AccountId::new([0xEEu8; 32]);
const NFT_DEFINITION_ID: AccountId = AccountId::new([0x03u8; 32]);
const TRANSFER_AMOUNT: u128 = 5_000;
const BURN_AMOUNT: u128 = 500;

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

fn token_handle(account_id: AccountId) -> AccountMeta {
    AccountMeta::new(account_id, false, TOKEN_PROGRAM_ID)
}

fn owner_account() -> AccountMeta {
    AccountMeta::balance(owner_id(), true)
}

fn unauthorized_owner_account() -> AccountMeta {
    AccountMeta::balance(owner_id(), false)
}

fn fungible_definition() -> ShardData {
    ShardData::from(&TokenDefinition::Fungible {
        name: "TEST".to_string(),
        total_supply: 1000,
        metadata_id: None,
    })
}

fn non_fungible_definition() -> ShardData {
    ShardData::from(&TokenDefinition::NonFungible {
        name: "NFT".to_string(),
        printable_supply: 5,
        metadata_id: AccountId::new([0u8; 32]),
    })
}

fn descriptor(definition_id: AccountId, kind: TokenKind) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind,
    }
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

// Drives the real entrypoint, so account arity, the PDA derivation and the planner's owner
// checks are all on the path a test exercises.
fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
    let instruction_data = borsh::to_vec(&instruction).expect("the instruction serializes");
    crate::execute(
        &ProgramInput {
            self_account_id: ATA_PROGRAM_ID,
            caller_account_id: None,
            accounts,
            instruction,
        },
        instruction_data,
    )
}

fn create_plan(
    owner: AccountMeta,
    ata: AccountMeta,
    kind: TokenKind,
    contents: AtaContents,
) -> Plan {
    plan_for(
        vec![owner, token_handle(definition_id()), ata],
        Instruction::Create {
            token_program_id: TOKEN_PROGRAM_ID,
            kind,
            contents,
        },
    )
}

fn contents_effect(definition_id: AccountId, kind: TokenKind, contents: AtaContents) -> Effect {
    Effect::AtaContents {
        token_program_id: TOKEN_PROGRAM_ID,
        descriptor: descriptor(definition_id, kind),
        contents,
    }
}

fn kind_effect(kind: TokenKind) -> Effect {
    Effect::DefinitionKind {
        token_program_id: TOKEN_PROGRAM_ID,
        kind,
    }
}

fn guard_on(program_account_id: AccountId, pre_data: &ShardData, effect: &Effect) {
    crate::resolve(&ResolveInput {
        self_account_id: ATA_PROGRAM_ID,
        selector: ProgramShardSelector::new(ata_id(), program_account_id),
        pre_data: pre_data.clone(),
        effect_data: borsh::to_vec(effect).expect("the effect serializes"),
    });
}

fn guard(pre_data: &ShardData, effect: &Effect) {
    guard_on(TOKEN_PROGRAM_ID, pre_data, effect);
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
    assert_ne!(
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
        ),
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), STRANGER_PROGRAM_ID),
        ),
        "each token program must get its own ATA family"
    );
}

#[test]
fn create_emits_chained_call_for_uninitialized_ata() {
    let plan = create_plan(
        unauthorized_owner_account(),
        token_handle(ata_id()),
        TokenKind::Fungible,
        AtaContents::Empty,
    );

    assert_eq!(
        plan.output().effects,
        vec![ShardEffect::new(
            &token_handle(ata_id()),
            &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Empty),
        )],
        "the claimed emptiness must be pinned to the account it describes"
    );
    assert_eq!(plan.output().chained_calls.len(), 1);
    assert_eq!(
        plan.output().chained_calls[0].program_account_id,
        TOKEN_PROGRAM_ID
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_panics_on_wrong_ata_address() {
    let _plan = create_plan(
        owner_account(),
        token_handle(AccountId::new([0xFFu8; 32])),
        TokenKind::Fungible,
        AtaContents::Empty,
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_naming_a_stranger_program_cannot_reach_the_real_ata() {
    let _plan = plan_for(
        vec![
            owner_account(),
            AccountMeta::new(definition_id(), false, STRANGER_PROGRAM_ID),
            AccountMeta::new(ata_id(), false, STRANGER_PROGRAM_ID),
        ],
        Instruction::Create {
            token_program_id: STRANGER_PROGRAM_ID,
            kind: TokenKind::Fungible,
            contents: AtaContents::Empty,
        },
    );
}

#[test]
fn create_leaves_a_matching_holding_untouched_however_the_owner_is_authorized() {
    let matches = [
        (
            definition_id(),
            fungible_definition(),
            TokenKind::Fungible,
            matching_holding(),
        ),
        (
            NFT_DEFINITION_ID,
            non_fungible_definition(),
            TokenKind::NftPrintedCopy,
            ShardData::from(&TokenHolding::NftMaster {
                definition_id: NFT_DEFINITION_ID,
                print_balance: 5,
            }),
        ),
        (
            NFT_DEFINITION_ID,
            non_fungible_definition(),
            TokenKind::NftPrintedCopy,
            ShardData::from(&TokenHolding::NftPrintedCopy {
                definition_id: NFT_DEFINITION_ID,
                owned: true,
            }),
        ),
    ];

    for (definition, definition_shard, kind, holding) in matches {
        for owner in [owner_account(), unauthorized_owner_account()] {
            let ata = token_handle(ata_of(definition));
            let plan = plan_for(
                vec![owner, token_handle(definition), ata.clone()],
                Instruction::Create {
                    token_program_id: TOKEN_PROGRAM_ID,
                    kind,
                    contents: AtaContents::Intended,
                },
            );

            assert!(plan.output().chained_calls.is_empty());
            assert_eq!(
                plan.output().effects,
                vec![
                    ShardEffect::new(
                        &ata,
                        &contents_effect(definition, kind, AtaContents::Intended)
                    ),
                    ShardEffect::new(&token_handle(definition), &kind_effect(kind)),
                ],
                "the no-op branch has no child call, so it pins the kind itself"
            );
        }

        guard(
            &holding,
            &contents_effect(definition, kind, AtaContents::Intended),
        );
        crate::create::check_definition_kind(&definition_shard, kind);
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

    let plan = create_plan(
        owner_account(),
        token_handle(ata_id()),
        TokenKind::Fungible,
        AtaContents::Squatted,
    );
    let [call] = <[_; 1]>::try_from(plan.output().chained_calls.clone()).unwrap();
    assert_eq!(call.program_account_id, TOKEN_PROGRAM_ID);
    assert_eq!(call.pda_seeds, vec![expected_seed]);
    assert_eq!(call.shard_selectors, expected_selectors);
    let decoded: token_core::Instruction = borsh::from_slice(&call.instruction_data).unwrap();
    assert!(matches!(
        decoded,
        token_core::Instruction::InitializeAccount {
            kind: TokenKind::Fungible
        }
    ));

    for shard in squats {
        guard(
            &shard,
            &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Squatted),
        );
    }
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn create_rejects_unauthorized_repair() {
    let _plan = create_plan(
        unauthorized_owner_account(),
        AccountMeta::new(ata_id(), true, TOKEN_PROGRAM_ID),
        TokenKind::Fungible,
        AtaContents::Squatted,
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_panics_on_wrong_address_even_over_a_matching_shard() {
    let _plan = create_plan(
        owner_account(),
        token_handle(AccountId::new([0xABu8; 32])),
        TokenKind::Fungible,
        AtaContents::Intended,
    );
}

#[test]
#[should_panic(expected = "Associated token account does not hold what the instruction claims")]
fn an_empty_claim_over_a_real_holding_is_rejected() {
    // Unguarded this is the whole attack: `Create` needs no owner signature on the empty branch,
    // and the chained `InitializeAccount` carries the ATA's own PDA seed, so the token program
    // would zeroize a funded holding for any caller who asks.
    guard(
        &matching_holding(),
        &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Empty),
    );
}

#[test]
#[should_panic(expected = "Associated token account does not hold what the instruction claims")]
fn a_squatted_claim_over_a_real_holding_is_rejected() {
    // The other route to the same clearing, this one costing the attacker the owner signature
    // the planner demands on that branch.
    guard(
        &matching_holding(),
        &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Squatted),
    );
}

#[test]
#[should_panic(expected = "Associated token account does not hold what the instruction claims")]
fn an_intended_claim_over_a_squat_is_rejected() {
    guard(
        &foreign_holding(),
        &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Intended),
    );
}

#[test]
#[should_panic(expected = "Associated token account does not hold what the instruction claims")]
fn an_intended_claim_over_an_empty_shard_is_rejected() {
    guard(
        &ShardData::empty(),
        &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Intended),
    );
}

#[test]
#[should_panic(expected = "Associated token account does not hold what the instruction claims")]
fn a_master_holding_is_not_the_intended_asset_of_a_fungible_definition() {
    guard(
        &ShardData::from(&TokenHolding::NftMaster {
            definition_id: definition_id(),
            print_balance: 5,
        }),
        &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Intended),
    );
}

#[test]
#[should_panic(expected = "Token Definition does not initialize this Token Holding kind")]
fn a_kind_the_definition_does_not_initialize_is_rejected() {
    // Without this the no-op branch could be justified against a kind no definition backs, which
    // turns a repair the owner asked for into a silent no-op.
    crate::create::check_definition_kind(&fungible_definition(), TokenKind::NftPrintedCopy);
}

#[test]
#[should_panic(expected = "only guards the Token Program's own shard")]
fn a_guard_aimed_at_a_shard_the_token_program_does_not_own_is_rejected() {
    // Every ATA effect ends in `Keep`, which `validate_resolution` never refuses for naming a
    // foreign shard. The bytes here would classify as `Empty`; the resolution is refused purely
    // because the handle names a shard whose contents the attacker, not the token program, wrote.
    guard_on(
        STRANGER_PROGRAM_ID,
        &ShardData::empty(),
        &contents_effect(definition_id(), TokenKind::Fungible, AtaContents::Empty),
    );
}

#[test]
fn transfer_delegates_the_proposed_descriptor_under_the_ata_seed() {
    const RECIPIENT_ID: AccountId = AccountId::new([0x77u8; 32]);
    let plan = plan_for(
        vec![
            owner_account(),
            token_handle(ata_id()),
            token_handle(RECIPIENT_ID),
        ],
        Instruction::Transfer {
            token_program_id: TOKEN_PROGRAM_ID,
            descriptor: descriptor(definition_id(), TokenKind::Fungible),
            amount: TRANSFER_AMOUNT,
        },
    );

    // Nothing is pinned here: the token program's `Withdraw` effect on the sender is what turns
    // the proposed descriptor into a fact, and it runs against the sender's real holding.
    assert!(plan.output().effects.is_empty());
    let [call] = <[_; 1]>::try_from(plan.output().chained_calls.clone()).unwrap();
    assert_eq!(call.program_account_id, TOKEN_PROGRAM_ID);
    assert_eq!(
        call.pda_seeds,
        vec![compute_ata_seed(
            owner_id(),
            definition_id(),
            TOKEN_PROGRAM_ID
        )]
    );
    assert_eq!(
        call.shard_selectors,
        vec![
            ProgramShardSelector::new(ata_id(), TOKEN_PROGRAM_ID),
            ProgramShardSelector::new(RECIPIENT_ID, TOKEN_PROGRAM_ID),
        ]
    );
    let decoded: token_core::Instruction = borsh::from_slice(&call.instruction_data).unwrap();
    assert!(matches!(
        decoded,
        token_core::Instruction::Transfer {
            amount_to_transfer: TRANSFER_AMOUNT,
            descriptor: TokenDescriptor {
                kind: TokenKind::Fungible,
                ..
            }
        }
    ));
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn transfer_with_a_forged_definition_id_cannot_reach_the_sender_ata() {
    let _plan = plan_for(
        vec![
            owner_account(),
            token_handle(ata_id()),
            token_handle(AccountId::new([0x77u8; 32])),
        ],
        Instruction::Transfer {
            token_program_id: TOKEN_PROGRAM_ID,
            descriptor: descriptor(AccountId::new([0x99u8; 32]), TokenKind::Fungible),
            amount: TRANSFER_AMOUNT,
        },
    );
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn transfer_rejects_an_unauthorized_owner() {
    let _plan = plan_for(
        vec![
            unauthorized_owner_account(),
            token_handle(ata_id()),
            token_handle(AccountId::new([0x77u8; 32])),
        ],
        Instruction::Transfer {
            token_program_id: TOKEN_PROGRAM_ID,
            descriptor: descriptor(definition_id(), TokenKind::Fungible),
            amount: TRANSFER_AMOUNT,
        },
    );
}

#[test]
fn burn_delegates_the_named_definition_under_the_ata_seed() {
    let plan = plan_for(
        vec![
            owner_account(),
            token_handle(ata_id()),
            token_handle(definition_id()),
        ],
        Instruction::Burn {
            token_program_id: TOKEN_PROGRAM_ID,
            kind: TokenKind::Fungible,
            amount: BURN_AMOUNT,
        },
    );

    assert!(plan.output().effects.is_empty());
    let [call] = <[_; 1]>::try_from(plan.output().chained_calls.clone()).unwrap();
    assert_eq!(
        call.pda_seeds,
        vec![compute_ata_seed(
            owner_id(),
            definition_id(),
            TOKEN_PROGRAM_ID
        )]
    );
    assert_eq!(
        call.shard_selectors,
        vec![
            ProgramShardSelector::new(definition_id(), TOKEN_PROGRAM_ID),
            ProgramShardSelector::new(ata_id(), TOKEN_PROGRAM_ID),
        ]
    );
    let decoded: token_core::Instruction = borsh::from_slice(&call.instruction_data).unwrap();
    assert!(matches!(
        decoded,
        token_core::Instruction::Burn {
            amount_to_burn: BURN_AMOUNT,
            kind: TokenKind::Fungible
        }
    ));
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn burn_naming_a_definition_the_ata_does_not_belong_to_is_rejected() {
    // The seed carries the named definition, so pointing the burn at another one lands outside
    // this owner's ATA family before the token program is ever reached.
    let _plan = plan_for(
        vec![
            owner_account(),
            token_handle(ata_id()),
            token_handle(NFT_DEFINITION_ID),
        ],
        Instruction::Burn {
            token_program_id: TOKEN_PROGRAM_ID,
            kind: TokenKind::Fungible,
            amount: BURN_AMOUNT,
        },
    );
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn burn_rejects_an_unauthorized_owner() {
    let _plan = plan_for(
        vec![
            unauthorized_owner_account(),
            token_handle(ata_id()),
            token_handle(definition_id()),
        ],
        Instruction::Burn {
            token_program_id: TOKEN_PROGRAM_ID,
            kind: TokenKind::Fungible,
            amount: BURN_AMOUNT,
        },
    );
}
