use lee_core::{
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff},
};
use token_core::{HoldingTarget, TokenDefinition, TokenHolding};

#[must_use]
pub fn burn(
    pre_states: Vec<AccountInput>,
    holder: &HoldingTarget,
    self_account_id: AccountId,
    amount_to_burn: u128,
) -> Vec<AccountStateDiff> {
    let ([definition_account, user_holding_account], owner_row) =
        crate::spend_rows(pre_states, holder.owner_id);

    let mut definition = TokenDefinition::try_from(definition_account.shard_of(self_account_id))
        .expect("Token Definition account must be valid");
    let mut holding = TokenHolding::try_from(user_holding_account.shard_of(self_account_id))
        .expect("Token Holding account must be valid");
    token_core::verify_holding(
        holder,
        &user_holding_account,
        self_account_id,
        holding.definition_id(),
        holding.kind(),
    );

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

    let definition_diff = AccountStateDiff::new(
        definition_account,
        BalanceDiff::Add(0),
        ShardData::from(&definition),
    );

    let holding_diff = AccountStateDiff::new(
        user_holding_account,
        BalanceDiff::Add(0),
        ShardData::from(&holding),
    );

    crate::with_owner_row(vec![definition_diff, holding_diff], owner_row)
}
