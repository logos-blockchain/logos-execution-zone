use lee_core::{
    account::{Data, Input, Slot},
    program::ProgramId,
};
use token_core::TokenHolding;

#[must_use]
pub fn print_nft(
    master_account: Input,
    printed_account: Input,
    self_program_id: ProgramId,
) -> Vec<Option<Slot>> {
    assert!(
        master_account.is_authorized,
        "Master NFT Account must be authorized"
    );

    assert!(
        printed_account.data(self_program_id).is_empty(),
        "Printed Account must be uninitialized"
    );

    let mut master_account_data = TokenHolding::try_from(master_account.data(self_program_id))
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

    let master_account_post = master_account
        .into_slot_of(self_program_id)
        .with_data(Data::from(&master_account_data));

    let printed_account_post = printed_account
        .into_slot_of(self_program_id)
        .with_data(Data::from(&TokenHolding::NftPrintedCopy {
            definition_id,
            owned: true,
        }));

    vec![Some(master_account_post), Some(printed_account_post)]
}
