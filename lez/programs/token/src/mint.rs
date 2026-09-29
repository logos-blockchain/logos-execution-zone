use lee_core::account::ShardData;
use token_core::TokenDefinition;

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
