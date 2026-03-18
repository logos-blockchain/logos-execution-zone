use nssa_core::{
    account::{Account, AccountWithMetadata, Data},
    program::AccountPostState,
};
use token_core::TokenHolding;

#[must_use]
pub fn print_nft(
    master_account: AccountWithMetadata,
    printed_account: AccountWithMetadata,
) -> Vec<AccountPostState> {
    assert!(
        master_account.is_authorized,
        "Master NFT Account must be authorized"
    );

    assert_eq!(
        printed_account.account,
        Account::default(),
        "Printed Account must be uninitialized"
    );

    let mut master_account_data =
        TokenHolding::try_from(&master_account.account.data).expect("Invalid Token Holding data");

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

    let mut master_account_post = master_account.account;
    master_account_post.data = Data::from(&master_account_data);

    let mut printed_account_post = printed_account.account;
    printed_account_post.data = Data::from(&TokenHolding::NftPrintedCopy {
        definition_id,
        owned: true,
    });

    vec![
        AccountPostState::new(master_account_post),
        AccountPostState::new_claimed(printed_account_post),
    ]
}
