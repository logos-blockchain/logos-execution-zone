use borsh::{BorshDeserialize, BorshSerialize};

use crate::account::{AccountId, Balance, ShardData};

pub const NATIVE_TOKEN_PROGRAM_ID: AccountId = AccountId::new([0; 32]);

/// Instruction type for the native token program.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`, both selecting the native shard.
    Transfer { amount: Balance },
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("native balance shard is not a canonical encoding")]
pub struct InvalidBalanceEncoding;

#[must_use]
pub fn encode_balance(balance: Balance) -> ShardData {
    if balance == 0 {
        ShardData::empty()
    } else {
        ShardData::try_from(balance.to_le_bytes().to_vec()).expect("an encoded balance is 16 bytes")
    }
}

pub fn decode_balance(data: &ShardData) -> Result<Balance, InvalidBalanceEncoding> {
    if data.is_empty() {
        return Ok(0);
    }
    let bytes = <[u8; 16]>::try_from(data.as_ref())
        .ok()
        .ok_or(InvalidBalanceEncoding)?;
    match Balance::from_le_bytes(bytes) {
        0 => Err(InvalidBalanceEncoding),
        balance => Ok(balance),
    }
}
