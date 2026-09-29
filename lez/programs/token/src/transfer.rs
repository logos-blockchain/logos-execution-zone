use lee_core::account::ShardData;
use token_core::{TokenDescriptor, TokenHolding};

#[must_use]
pub fn withdraw(pre_data: &ShardData, descriptor: &TokenDescriptor, amount: u128) -> ShardData {
    let mut holding = TokenHolding::try_from(pre_data).expect("Invalid sender data");
    assert_kind(&holding, descriptor);

    match &mut holding {
        TokenHolding::Fungible { balance, .. } => {
            *balance = balance.checked_sub(amount).expect("Insufficient balance");
        }
        TokenHolding::NftMaster { print_balance, .. } => {
            assert_eq!(
                *print_balance, amount,
                "Invalid balance for NFT Master transfer"
            );
            *print_balance = 0;
        }
        TokenHolding::NftPrintedCopy { owned, .. } => {
            assert_eq!(amount, 1, "Invalid balance for NFT Printed Copy transfer");
            assert!(*owned, "Sender does not own the NFT Printed Copy");
            *owned = false;
        }
    }

    ShardData::from(&holding)
}

#[must_use]
pub fn deposit(pre_data: &ShardData, descriptor: &TokenDescriptor, amount: u128) -> ShardData {
    let mut holding = if pre_data.is_empty() {
        descriptor.zeroized()
    } else {
        TokenHolding::try_from(pre_data).expect("Invalid recipient data")
    };
    assert_kind(&holding, descriptor);

    match &mut holding {
        TokenHolding::Fungible { balance, .. } => {
            *balance = balance
                .checked_add(amount)
                .expect("Recipient balance overflow");
        }
        TokenHolding::NftMaster { print_balance, .. } => {
            assert_eq!(
                *print_balance, 0,
                "Invalid balance in recipient account for NFT transfer"
            );
            *print_balance = amount;
        }
        TokenHolding::NftPrintedCopy { owned, .. } => {
            assert_eq!(amount, 1, "Invalid balance for NFT Printed Copy transfer");
            assert!(!*owned, "Recipient already owns the NFT Printed Copy");
            *owned = true;
        }
    }

    ShardData::from(&holding)
}

pub(crate) fn assert_kind(holding: &TokenHolding, descriptor: &TokenDescriptor) {
    assert_eq!(
        holding.definition_id(),
        descriptor.definition_id,
        "Mismatch Token Definition and Token Holding"
    );
    assert_eq!(
        holding.kind(),
        descriptor.kind,
        "Mismatched Token Definition and Token Holding types"
    );
}
