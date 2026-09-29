use lee_core::account::{AccountId, ShardData};
use token_core::TokenHolding;

#[must_use]
pub fn print_copy(pre_data: &ShardData, definition_id: AccountId) -> ShardData {
    let mut master_account_data =
        TokenHolding::try_from(pre_data).expect("Invalid Token Holding data");

    let TokenHolding::NftMaster {
        definition_id: master_definition_id,
        print_balance,
    } = &mut master_account_data
    else {
        panic!("Invalid Token Holding provided as NFT Master Account");
    };

    assert_eq!(
        *master_definition_id, definition_id,
        "Printed copy does not belong to the master's Token Definition"
    );

    assert!(
        *print_balance > 1,
        "Insufficient balance to print another NFT copy"
    );
    *print_balance = print_balance.checked_sub(1).expect("Checked above");

    ShardData::from(&master_account_data)
}
