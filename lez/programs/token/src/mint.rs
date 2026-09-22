use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountMeta, Plan},
};
use token_core::{TokenDefinition, TokenHolding};

use crate::Effect;

pub fn mint(
    plan: &mut Plan,
    definition_account: &AccountMeta,
    user_holding_account: &AccountMeta,
    amount_to_mint: u128,
) {
    assert!(
        definition_account.is_authorized,
        "Definition authorization is missing"
    );

    plan.update(
        definition_account,
        &Effect::MintSupply {
            amount: amount_to_mint,
        },
    );
    plan.update(
        user_holding_account,
        &Effect::MintHolding {
            definition_id: definition_account.account_id,
            amount: amount_to_mint,
        },
    );
}

#[must_use]
pub fn mint_supply(pre_data: &ShardData, amount_to_mint: u128) -> ShardData {
    let mut definition =
        TokenDefinition::try_from(pre_data).expect("Token Definition account must be valid");

    let TokenDefinition::Fungible { total_supply, .. } = &mut definition else {
        panic!("Cannot mint additional supply for Non-Fungible Tokens");
    };
    *total_supply = total_supply
        .checked_add(amount_to_mint)
        .expect("Total supply overflow");

    ShardData::from(&definition)
}

#[must_use]
pub fn mint_holding(
    pre_data: &ShardData,
    definition_id: AccountId,
    amount_to_mint: u128,
) -> ShardData {
    let mut holding = if pre_data.is_empty() {
        TokenHolding::Fungible {
            definition_id,
            balance: 0,
        }
    } else {
        TokenHolding::try_from(pre_data).expect("Token Holding account must be valid")
    };

    assert_eq!(
        definition_id,
        holding.definition_id(),
        "Mismatch Token Definition and Token Holding"
    );

    let TokenHolding::Fungible { balance, .. } = &mut holding else {
        panic!("Mismatched Token Definition and Token Holding types");
    };
    *balance = balance
        .checked_add(amount_to_mint)
        .expect("Balance overflow on minting");

    ShardData::from(&holding)
}
