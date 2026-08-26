use lee_core::{
    account::{Data, Input, Slot},
    program::ProgramId,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn burn(
    definition_account: Input,
    user_holding_account: Input,
    amount_to_burn: u128,
    self_program_id: ProgramId,
) -> Vec<Option<Slot>> {
    assert!(
        user_holding_account.is_authorized,
        "Authorization is missing"
    );

    let mut definition = TokenDefinition::try_from(definition_account.data(self_program_id))
        .expect("Token Definition account must be valid");
    let mut holding = TokenHolding::try_from(user_holding_account.data(self_program_id))
        .expect("Token Holding account must be valid");

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
                .checked_sub(amount_to_burn)
                .expect("Insufficient balance to burn");

            *total_supply = total_supply
                .checked_sub(amount_to_burn)
                .expect("Total supply underflow");
        }
        (
            TokenDefinition::NonFungible {
                name: _,
                printable_supply,
                metadata_id: _,
            },
            TokenHolding::NftMaster {
                definition_id: _,
                print_balance,
            },
        ) => {
            *printable_supply = printable_supply
                .checked_sub(amount_to_burn)
                .expect("Printable supply underflow");

            *print_balance = print_balance
                .checked_sub(amount_to_burn)
                .expect("Insufficient balance to burn");
        }
        (
            TokenDefinition::NonFungible {
                name: _,
                printable_supply,
                metadata_id: _,
            },
            TokenHolding::NftPrintedCopy {
                definition_id: _,
                owned,
            },
        ) => {
            assert_eq!(
                amount_to_burn, 1,
                "Invalid balance to burn for NFT Printed Copy"
            );

            assert!(*owned, "Cannot burn unowned NFT Printed Copy");

            *printable_supply = printable_supply
                .checked_sub(1)
                .expect("Printable supply underflow");

            *owned = false;
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
