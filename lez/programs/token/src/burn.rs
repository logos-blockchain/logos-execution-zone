use lee_core::account::ShardData;
use token_core::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind};

#[must_use]
pub fn burn_supply(pre_data: &ShardData, kind: TokenKind, amount_to_burn: u128) -> ShardData {
    let mut definition =
        TokenDefinition::try_from(pre_data).expect("Token Definition account must be valid");

    match (&mut definition, kind) {
        (TokenDefinition::Fungible { total_supply, .. }, TokenKind::Fungible) => {
            *total_supply = total_supply
                .checked_sub(amount_to_burn)
                .expect("Total supply underflow");
        }
        (
            TokenDefinition::NonFungible {
                printable_supply, ..
            },
            TokenKind::NftMaster,
        ) => {
            *printable_supply = printable_supply
                .checked_sub(amount_to_burn)
                .expect("Printable supply underflow");
        }
        (
            TokenDefinition::NonFungible {
                printable_supply, ..
            },
            TokenKind::NftPrintedCopy,
        ) => {
            assert_eq!(
                amount_to_burn, 1,
                "Invalid balance to burn for NFT Printed Copy"
            );
            *printable_supply = printable_supply
                .checked_sub(1)
                .expect("Printable supply underflow");
        }
        _ => panic!("Mismatched Token Definition and Token Holding types"),
    }

    ShardData::from(&definition)
}

#[must_use]
pub fn burn_holding(
    pre_data: &ShardData,
    descriptor: &TokenDescriptor,
    amount_to_burn: u128,
) -> ShardData {
    let mut holding =
        TokenHolding::try_from(pre_data).expect("Token Holding account must be valid");
    crate::transfer::assert_kind(&holding, descriptor);

    match &mut holding {
        TokenHolding::Fungible { balance, .. } => {
            *balance = balance
                .checked_sub(amount_to_burn)
                .expect("Insufficient balance to burn");
        }
        TokenHolding::NftMaster { print_balance, .. } => {
            *print_balance = print_balance
                .checked_sub(amount_to_burn)
                .expect("Insufficient balance to burn");
        }
        TokenHolding::NftPrintedCopy { owned, .. } => {
            assert_eq!(
                amount_to_burn, 1,
                "Invalid balance to burn for NFT Printed Copy"
            );
            assert!(*owned, "Cannot burn unowned NFT Printed Copy");
            *owned = false;
        }
    }

    ShardData::from(&holding)
}
