use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::ProgramId,
};
use token_core::TokenHolding;


fn debit(holding: &mut TokenHolding, balance_to_move: u128) {
    match holding {
        TokenHolding::Fungible { balance, .. } => {
            *balance = balance
                .checked_sub(balance_to_move)
                .expect("Insufficient balance");
        }
        TokenHolding::NftMaster { print_balance, .. } => {
            assert_eq!(
                *print_balance, balance_to_move,
                "Invalid balance for NFT Master transfer"
            );
            *print_balance = 0;
        }
        TokenHolding::NftPrintedCopy { owned, .. } => {
            assert_eq!(
                balance_to_move, 1,
                "Invalid balance for NFT Printed Copy transfer"
            );
            assert!(*owned, "Sender does not own the NFT Printed Copy");
            *owned = false;
        }
    }
}

fn credit(holding: &mut TokenHolding, balance_to_move: u128) {
    match holding {
        TokenHolding::Fungible { balance, .. } => {
            *balance = balance
                .checked_add(balance_to_move)
                .expect("Recipient balance overflow");
        }
        TokenHolding::NftMaster { print_balance, .. } => {
            assert_eq!(
                *print_balance, 0,
                "Invalid balance in recipient account for NFT transfer"
            );
            *print_balance = balance_to_move;
        }
        TokenHolding::NftPrintedCopy { owned, .. } => {
            assert_eq!(
                balance_to_move, 1,
                "Invalid balance for NFT Printed Copy transfer"
            );
            assert!(!*owned, "Recipient already owns the NFT Printed Copy");
            *owned = true;
        }
    }
}

#[must_use]
pub fn transfer(
    sender: AccountWithMetadata,
    recipient: AccountWithMetadata,
    balance_to_move: u128,
    self_program_id: ProgramId,
) -> Vec<Account> {
    assert!(
        sender.is_authorized,
        "Sender authorization is missing"
    );

    let mut sender_holding =
        TokenHolding::try_from(sender.account.data(self_program_id)).expect("Invalid sender data");

    // One address may play both roles; debiting and crediting the single holding keeps the
    // two posts equal by construction.
    if sender.account_id == recipient.account_id {
        debit(&mut sender_holding, balance_to_move);
        credit(&mut sender_holding, balance_to_move);

        let mut joint = sender.account;
        joint.slot_mut(self_program_id).data = Data::from(&sender_holding);
        return vec![joint.clone(), joint];
    }

    let mut recipient_holding = if recipient.account.slot(self_program_id).is_none() {
        TokenHolding::zeroized_clone_from(&sender_holding)
    } else {
        TokenHolding::try_from(recipient.account.data(self_program_id))
            .expect("Invalid recipient data")
    };

    assert_eq!(
        sender_holding.definition_id(),
        recipient_holding.definition_id(),
        "Sender and recipient definition id mismatch"
    );
    assert_eq!(
        std::mem::discriminant(&sender_holding),
        std::mem::discriminant(&recipient_holding),
        "Mismatched token holding types for transfer"
    );

    debit(&mut sender_holding, balance_to_move);
    credit(&mut recipient_holding, balance_to_move);

    let mut sender_post = sender.account;
    sender_post.slot_mut(self_program_id).data = Data::from(&sender_holding);

    let mut recipient_post = recipient.account;
    recipient_post.slot_mut(self_program_id).data = Data::from(&recipient_holding);

    vec![sender_post, recipient_post]
}
