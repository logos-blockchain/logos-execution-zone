use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::ProgramId,
};
use token_core::{TokenDefinition, TokenHolding};


#[must_use]
pub fn mint(
    definition_account: AccountWithMetadata,
    user_holding_account: AccountWithMetadata,
    amount_to_mint: u128,
    self_program_id: ProgramId,
) -> Vec<Account> {
    assert!(
        definition_account.is_authorized,
        "Definition authorization is missing"
    );

    let mut definition =
        TokenDefinition::try_from(definition_account.account.data(self_program_id))
            .expect("Token Definition account must be valid");
    let mut holding = if user_holding_account.account.slot(self_program_id).is_none() {
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition)
    } else {
        TokenHolding::try_from(user_holding_account.account.data(self_program_id))
            .expect("Token Holding account must be valid")
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

    let mut definition_post = definition_account.account;
    definition_post.slot_mut(self_program_id).data = Data::from(&definition);

    let mut holding_post = user_holding_account.account;
    holding_post.slot_mut(self_program_id).data = Data::from(&holding);

    vec![definition_post, holding_post]
}
