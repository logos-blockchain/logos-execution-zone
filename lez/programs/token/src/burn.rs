use lee_core::{
    account::ShardData,
    program::{AccountMeta, Plan},
};
use token_core::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind};

use crate::Effect;

pub fn burn(
    plan: &mut Plan,
    definition_account: &AccountMeta,
    user_holding_account: &AccountMeta,
    kind: TokenKind,
    amount_to_burn: u128,
) {
    assert!(
        user_holding_account.is_authorized,
        "Authorization is missing"
    );

    // The holding's kind picks which supply the definition decrements, so it crosses into the
    // definition's effect. Both sides check it against their own contents.
    plan.effect(
        definition_account,
        &Effect::BurnSupply {
            kind,
            amount: amount_to_burn,
        },
    );
    plan.effect(
        user_holding_account,
        &Effect::BurnHolding {
            descriptor: TokenDescriptor {
                definition_id: definition_account.account_id,
                kind,
            },
            amount: amount_to_burn,
        },
    );
}

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
