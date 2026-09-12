use lee_core::{
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff},
};
use token_core::{HoldingKind, HoldingTarget, TokenHolding};

#[must_use]
pub fn print_nft(
    pre_states: Vec<AccountInput>,
    master_holder: &HoldingTarget,
    copy_holder: &HoldingTarget,
    self_account_id: AccountId,
) -> Vec<AccountStateDiff> {
    let ([master_account, printed_account], owner_row) =
        crate::spend_rows(pre_states, master_holder.owner_id);

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
    token_core::verify_holding(
        master_holder,
        &master_account,
        self_account_id,
        definition_id,
        HoldingKind::NftMaster,
    );
    token_core::verify_holding(
        copy_holder,
        &printed_account,
        self_account_id,
        definition_id,
        HoldingKind::NftPrintedCopy,
    );

    let printed_shard = printed_account.shard_of(self_account_id);
    assert!(
        printed_shard.is_empty()
            || TokenHolding::try_from(printed_shard).expect("Invalid Token Holding data")
                == TokenHolding::NftPrintedCopy {
                    definition_id,
                    owned: false,
                },
        "Printed Account already holds a copy"
    );

    assert!(
        *print_balance > 1,
        "Insufficient balance to print another NFT copy"
    );
    *print_balance = print_balance.checked_sub(1).expect("Checked above");

    let master_diff = AccountStateDiff::new(
        master_account,
        BalanceDiff::Add(0),
        ShardData::from(&master_account_data),
    );

    let printed_diff = AccountStateDiff::new(
        printed_account,
        BalanceDiff::Add(0),
        ShardData::from(&TokenHolding::NftPrintedCopy {
            definition_id,
            owned: true,
        }),
    );

    crate::with_owner_row(vec![master_diff, printed_diff], owner_row)
}
