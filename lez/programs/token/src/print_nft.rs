use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountMeta, Plan, Proposed},
};
use token_core::TokenHolding;

use crate::Effect;

pub fn print_nft(
    plan: &mut Plan,
    master_account: &AccountMeta,
    printed_account: &AccountMeta,
    definition_id: AccountId,
) {
    assert!(
        master_account.is_authorized,
        "Master NFT Account must be authorized"
    );

    // The printed copy's collection identity comes from the master, whose shard the printed
    // account's resolver never sees; the master's own effect is what pins it.
    let definition_id = plan
        .require(
            master_account,
            &Effect::PrintCopy { definition_id },
            Proposed::new(definition_id),
        )
        .get();

    plan.update(
        printed_account,
        &Effect::CreatePrintedCopy { definition_id },
    );
}

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

#[must_use]
pub fn create_printed_copy(pre_data: &ShardData, definition_id: AccountId) -> ShardData {
    assert!(
        pre_data.is_empty(),
        "Printed Account must not already hold data"
    );

    ShardData::from(&TokenHolding::NftPrintedCopy {
        definition_id,
        owned: true,
    })
}
