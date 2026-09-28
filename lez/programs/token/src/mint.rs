use lee_core::{
    account::ShardData,
    program::{AccountMeta, Plan},
};
use token_core::{TokenDefinition, TokenDescriptor, TokenKind};

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

    plan.effect(
        definition_account,
        &Effect::MintSupply {
            amount: amount_to_mint,
        },
    );
    plan.effect(
        user_holding_account,
        &Effect::Deposit {
            descriptor: TokenDescriptor {
                definition_id: definition_account.account_id,
                kind: TokenKind::Fungible,
            },
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
