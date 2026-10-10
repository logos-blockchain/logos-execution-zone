use lee_core::account::AccountId;
use token_core::{NewTokenDefinition, TokenDefinition, TokenHolding};

#[must_use]
pub fn definition(
    new: NewTokenDefinition,
    definition_id: AccountId,
    metadata_id: Option<AccountId>,
) -> (TokenDefinition, TokenHolding) {
    match new {
        NewTokenDefinition::Fungible { name, total_supply } => (
            TokenDefinition::Fungible {
                name,
                total_supply,
                metadata_id,
            },
            TokenHolding::Fungible {
                definition_id,
                balance: total_supply,
            },
        ),
        NewTokenDefinition::NonFungible {
            name,
            printable_supply,
        } => (
            TokenDefinition::NonFungible {
                name,
                printable_supply,
                metadata_id: metadata_id.expect("A non-fungible definition needs metadata"),
            },
            TokenHolding::NftMaster {
                definition_id,
                print_balance: printable_supply,
            },
        ),
    }
}
