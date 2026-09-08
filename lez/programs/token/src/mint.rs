use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data},
    program::AccountStateDiff,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn mint(
    definition_account: &AccountInput,
    user_holding_account: &AccountInput,
    self_account_id: AccountId,
    amount_to_mint: u128,
) -> Vec<AccountStateDiff> {
    assert!(
        definition_account.is_authorized,
        "Definition authorization is missing"
    );

    let mut definition = TokenDefinition::try_from(definition_account.shard_of(self_account_id))
        .expect("Token Definition account must be valid");
    let holding_shard = user_holding_account.shard_of(self_account_id);
    let mut holding = if holding_shard.is_empty() {
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition)
    } else {
        TokenHolding::try_from(holding_shard).expect("Token Holding account must be valid")
    };

    assert_eq!(
        definition_account.account_id,
        holding.definition_id(),
        "Mismatch Token Definition and Token Holding"
    );

    match (&mut definition, &mut holding) {
        (
            TokenDefinition::Fungible {
                name: _,
                metadata_id: _,
                total_supply,
            },
            TokenHolding::Fungible {
                definition_id: _,
                balance,
            },
        ) => {
            *balance = balance
                .checked_add(amount_to_mint)
                .expect("Balance overflow on minting");

            *total_supply = total_supply
                .checked_add(amount_to_mint)
                .expect("Total supply overflow");
        }
        (
            TokenDefinition::NonFungible { .. },
            TokenHolding::NftMaster { .. } | TokenHolding::NftPrintedCopy { .. },
        ) => {
            panic!("Cannot mint additional supply for Non-Fungible Tokens");
        }
        _ => panic!("Mismatched Token Definition and Token Holding types"),
    }

    let definition_diff = AccountStateDiff::new(
        definition_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&definition),
    );

    let holding_diff = AccountStateDiff::new(
        user_holding_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&holding),
    );

    vec![definition_diff, holding_diff]
}
