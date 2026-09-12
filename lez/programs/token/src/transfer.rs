use lee_core::{
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff},
};
use token_core::{HoldingTarget, TokenHolding};

#[must_use]
pub fn transfer(
    pre_states: Vec<AccountInput>,
    sender: &HoldingTarget,
    recipient: &HoldingTarget,
    self_account_id: AccountId,
    balance_to_move: u128,
) -> Vec<AccountStateDiff> {
    let ([sender_account, recipient_account], owner_row) =
        crate::spend_rows(pre_states, sender.owner_id);

    let mut sender_holding = TokenHolding::try_from(sender_account.shard_of(self_account_id))
        .expect("Invalid sender data");
    let (definition_id, kind) = (sender_holding.definition_id(), sender_holding.kind());
    token_core::verify_holding(
        sender,
        &sender_account,
        self_account_id,
        definition_id,
        kind,
    );
    token_core::verify_holding(
        recipient,
        &recipient_account,
        self_account_id,
        definition_id,
        kind,
    );

    let recipient_shard = recipient_account.shard_of(self_account_id);
    let mut recipient_holding = if recipient_shard.is_empty() {
        TokenHolding::zeroized_clone_from(&sender_holding)
    } else {
        TokenHolding::try_from(recipient_shard).expect("Invalid recipient data")
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

    let sender_diff = AccountStateDiff::new(
        sender_account,
        BalanceDiff::Add(0),
        ShardData::from(&sender_holding),
    );

    let recipient_diff = AccountStateDiff::new(
        recipient_account,
        BalanceDiff::Add(0),
        ShardData::from(&recipient_holding),
    );

    crate::with_owner_row(vec![sender_diff, recipient_diff], owner_row)
}
