use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    account::{AccountId, Actor, Balance, ShardData},
    program::{Envelope, PdaSeed, ReceiveInput, Response, Transition},
};

/// Hardcoded native token shard address.
pub const NATIVE_TOKEN_PROGRAM_ID: AccountId = AccountId::new([0; 32]);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Transfer {
        to: AccountId,
        amount: Balance,
        expect_balance: Option<Balance>,
    },
    Credit(Balance),
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum TransferError {
    #[error("native transfer message does not decode")]
    InvalidMessage,
    #[error("native transfer recipient is the sender")]
    InvalidInputs,
    #[error("native transfer sender {account_id} is not authorized")]
    UnauthorizedSender { account_id: AccountId },
    #[error("native credit to {account_id} was not sent by a native transfer")]
    ForeignCredit { account_id: AccountId },
    #[error(transparent)]
    InvalidBalance(#[from] InvalidBalanceEncoding),
    #[error("sender {account_id} holds {actual}, not the expected {expected}")]
    BalanceMismatch {
        account_id: AccountId,
        expected: Balance,
        actual: Balance,
    },
    #[error("sender {account_id} holds less than the transferred amount")]
    InsufficientBalance { account_id: AccountId },
    #[error("recipient {account_id} balance overflows")]
    BalanceOverflow { account_id: AccountId },
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

pub fn decode_balance(data: &[u8]) -> Result<Balance, InvalidBalanceEncoding> {
    if data.is_empty() {
        return Ok(0);
    }
    let bytes = <[u8; 16]>::try_from(data)
        .ok()
        .ok_or(InvalidBalanceEncoding)?;
    match Balance::from_le_bytes(bytes) {
        0 => Err(InvalidBalanceEncoding),
        balance => Ok(balance),
    }
}

pub fn receive(input: &ReceiveInput) -> Result<Transition, TransferError> {
    let Ok(message) = borsh::from_slice::<Message>(&input.message) else {
        return Err(TransferError::InvalidMessage);
    };
    let account_id = input.receiver.account_id;
    let response = match message {
        Message::Transfer {
            to,
            amount,
            expect_balance,
        } => {
            if to == account_id {
                return Err(TransferError::InvalidInputs);
            }
            if !input.is_authorized {
                return Err(TransferError::UnauthorizedSender { account_id });
            }
            let balance = decode_balance(&input.pre_data)?;
            if let Some(expected) = expect_balance
                && balance != expected
            {
                return Err(TransferError::BalanceMismatch {
                    account_id,
                    expected,
                    actual: balance,
                });
            }
            let post = balance
                .checked_sub(amount)
                .ok_or(TransferError::InsufficientBalance { account_id })?;
            Response::write(encode_balance(post)).send(Envelope::new(
                Actor::native_balance(to),
                &Message::Credit(amount),
            ))
        }
        Message::Credit(amount) => {
            if !input.from_own_program() {
                return Err(TransferError::ForeignCredit { account_id });
            }
            let post = decode_balance(&input.pre_data)?
                .checked_add(amount)
                .ok_or(TransferError::BalanceOverflow { account_id })?;
            Response::write(encode_balance(post))
        }
    };
    Ok(response.into_transition(input.clone()))
}

/// A transfer out of an account the caller holds under `seed`.
#[must_use]
pub fn custody_transfer(
    from: AccountId,
    seed: PdaSeed,
    to: AccountId,
    amount: Balance,
) -> Envelope {
    Envelope::new(
        Actor::native_balance(from),
        &Message::Transfer {
            to,
            amount,
            expect_balance: None,
        },
    )
    .with_pda_seeds(vec![seed])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_balance_round_trips_through_the_codec() {
        for balance in [1, 42, u128::from(u64::MAX), Balance::MAX] {
            assert_eq!(decode_balance(&encode_balance(balance)), Ok(balance));
        }
        assert!(encode_balance(0).is_empty());
        assert_eq!(decode_balance(&ShardData::empty()), Ok(0));
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        for bytes in [vec![0; 16], vec![1], vec![1; 15], vec![1; 17], vec![0; 32]] {
            let data = ShardData::try_from(bytes.clone()).expect("fits the shard limit");
            assert_eq!(
                decode_balance(&data),
                Err(InvalidBalanceEncoding),
                "{bytes:?} decoded as a balance"
            );
        }
    }
}
