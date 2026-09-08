use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data},
    program::AccountStateDiff,
};
use token_core::TokenHolding;

#[must_use]
pub fn print_nft(
    master_account: &AccountInput,
    printed_account: &AccountInput,
    self_account_id: AccountId,
) -> Vec<AccountStateDiff> {
    assert!(
        master_account.is_authorized,
        "Master NFT Account must be authorized"
    );

    assert!(
        printed_account.shard_of(self_account_id).is_empty(),
        "Printed Account must not already hold data"
    );

    let mut master_account_data = TokenHolding::try_from(master_account.shard_of(self_account_id))
        .expect("Invalid Token Holding data");

    let TokenHolding::NftMaster {
        definition_id,
        print_balance,
    } = &mut master_account_data
    else {
        panic!("Invalid Token Holding provided as NFT Master Account");
    };

    let definition_id = *definition_id;

    assert!(
        *print_balance > 1,
        "Insufficient balance to print another NFT copy"
    );
    *print_balance = print_balance.checked_sub(1).expect("Checked above");

    let master_diff = AccountStateDiff::new(
        master_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&master_account_data),
    );

    let printed_diff = AccountStateDiff::new(
        printed_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&TokenHolding::NftPrintedCopy {
            definition_id,
            owned: true,
        }),
    );

    vec![master_diff, printed_diff]
}
