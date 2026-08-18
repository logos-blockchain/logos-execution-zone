use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountDiffOutput, Claim},
};
use token_core::TokenHolding;

#[must_use]
pub fn print_nft(
    master_account: &AccountWithMetadata,
    printed_account: &AccountWithMetadata,
) -> Vec<AccountDiffOutput> {
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

    vec![
        AccountDiffOutput::new(AccountDiff {
            id: master_account.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(Data::from(&master_account_data).as_ref().to_vec()),
        }),
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: printed_account.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(
                    Data::from(&TokenHolding::NftPrintedCopy {
                        definition_id,
                        owned: true,
                    })
                    .as_ref()
                    .to_vec(),
                ),
            },
            Claim::Authorized,
        ),
    ]
}
