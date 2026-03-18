use nssa_core::{
    account::{Account, AccountWithMetadata, Data},
    program::AccountPostState,
};
use token_core::TokenHolding;

#[must_use]
pub fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
) -> Vec<AccountPostState> {
    assert!(sender.is_authorized, "Sender authorization is missing");

    let mut sender_holding =
        TokenHolding::try_from(&sender.account.data).expect("Invalid sender data");

    let mut recipient_holding = if recipient.account == Account::default() {
        TokenHolding::zeroized_clone_from(&sender_holding)
    } else {
        TokenHolding::try_from(&recipient.account.data).expect("Invalid recipient data")
    };

    assert_eq!(
        sender_holding.definition_id(),
        recipient_holding.definition_id(),
        "Sender and recipient definition id mismatch"
    );

    match (&mut sender_holding, &mut recipient_holding) {
        (
            TokenHolding::Fungible {
                definition_id: _,
                balance: sender_balance,
            },
            TokenHolding::Fungible {
                definition_id: _,
                balance: recipient_balance,
            },
        ) => {
            *sender_balance = sender_balance
                .checked_sub(balance_to_move)
                .expect("Insufficient balance");

            *recipient_balance = recipient_balance
                .checked_add(balance_to_move)
                .expect("Recipient balance overflow");
        }
        (
            TokenHolding::NftMaster {
                definition_id: _,
                print_balance: sender_print_balance,
            },
            TokenHolding::NftMaster {
                definition_id: _,
                print_balance: recipient_print_balance,
            },
        ) => {
            assert_eq!(
                *recipient_print_balance, 0,
                "Invalid balance in recipient account for NFT transfer"
            );

            assert_eq!(
                *sender_print_balance, balance_to_move,
                "Invalid balance for NFT Master transfer"
            );

            std::mem::swap(sender_print_balance, recipient_print_balance);
        }
        (
            TokenHolding::NftPrintedCopy {
                definition_id: _,
                owned: sender_owned,
            },
            TokenHolding::NftPrintedCopy {
                definition_id: _,
                owned: recipient_owned,
            },
        ) => {
            assert_eq!(
                balance_to_move, 1,
                "Invalid balance for NFT Printed Copy transfer"
            );

            assert!(*sender_owned, "Sender does not own the NFT Printed Copy");

            assert!(
                !*recipient_owned,
                "Recipient already owns the NFT Printed Copy"
            );

            *sender_owned = false;
            *recipient_owned = true;
        }
        _ => {
            panic!("Mismatched token holding types for transfer");
        }
    }

    let mut sender_post = sender.account;
    sender_post.data = Data::from(&sender_holding);

    let mut recipient_post = recipient.account;
    recipient_post.data = Data::from(&recipient_holding);

    vec![
        AccountPostState::new(sender_post),
        AccountPostState::new_claimed_if_default(recipient_post),
    ]
}
