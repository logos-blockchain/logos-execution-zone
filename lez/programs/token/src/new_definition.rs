use lee_core::account::AccountId;
use token_core::{NewTokenDefinition, TokenDefinition};

#[must_use]
pub fn definition(new: NewTokenDefinition, metadata_id: Option<AccountId>) -> TokenDefinition {
    match new {
        NewTokenDefinition::Fungible { name, total_supply } => TokenDefinition::Fungible {
            name,
            total_supply,
            metadata_id,
        },
        NewTokenDefinition::NonFungible {
            name,
            printable_supply,
        } => TokenDefinition::NonFungible {
            name,
            printable_supply,
            metadata_id: metadata_id.expect("A non-fungible definition needs metadata"),
        },
    }
}
