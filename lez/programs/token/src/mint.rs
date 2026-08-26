use lee_core::{
    account::{Data, Input, Slot},
    program::ProgramId,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn mint(
    definition_account: Input,
    user_holding_account: Input,
    amount_to_mint: u128,
    self_program_id: ProgramId,
) -> Vec<Option<Slot>> {
    assert!(
        definition_account.is_authorized,
        "Definition authorization is missing"
    );

    let mut definition = TokenDefinition::try_from(definition_account.data(self_program_id))
        .expect("Token Definition account must be valid");
    let mut holding = if user_holding_account.data(self_program_id).is_empty() {
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition)
    } else {
        TokenHolding::try_from(user_holding_account.data(self_program_id))
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

    let definition_post = definition_account
        .into_slot_of(self_program_id)
        .with_data(Data::from(&definition));

    let holding_post = user_holding_account
        .into_slot_of(self_program_id)
        .with_data(Data::from(&holding));

    vec![Some(definition_post), Some(holding_post)]
}
