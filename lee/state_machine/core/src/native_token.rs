use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    account::{AccountId, Balance, ProgramShardSelector, ShardData},
    program::{
        AccountInput, AccountStateDiff, ChainedCall, InstructionData, PdaSeed, ProgramOutput,
    },
};

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
pub enum TransferError {
    #[error("native transfer instruction does not decode")]
    InvalidInstruction,
    #[error("native transfer takes a sender and a recipient row, both selecting the native shard")]
    InvalidInputs,
    #[error("native transfer sender {account_id} is not authorized")]
    UnauthorizedSender { account_id: AccountId },
    #[error(transparent)]
    InvalidBalance(#[from] InvalidBalanceEncoding),
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

pub fn execute(
    caller_account_id: Option<AccountId>,
    pre_states: &[AccountInput],
    instruction_data: &InstructionData,
) -> Result<ProgramOutput, TransferError> {
    let Ok(Instruction::Transfer { amount }) = borsh::from_slice(instruction_data) else {
        return Err(TransferError::InvalidInstruction);
    };

    let [sender, recipient] = pre_states else {
        return Err(TransferError::InvalidInputs);
    };
    if sender.program_account_id() != NATIVE_TOKEN_PROGRAM_ID
        || recipient.program_account_id() != NATIVE_TOKEN_PROGRAM_ID
        || sender.account_id == recipient.account_id
    {
        return Err(TransferError::InvalidInputs);
    }
    if !sender.is_authorized {
        return Err(TransferError::UnauthorizedSender {
            account_id: sender.account_id,
        });
    }

    let sent = decode_balance(&sender.shard.1)?.checked_sub(amount).ok_or(
        TransferError::InsufficientBalance {
            account_id: sender.account_id,
        },
    )?;
    let received = decode_balance(&recipient.shard.1)?
        .checked_add(amount)
        .ok_or(TransferError::BalanceOverflow {
            account_id: recipient.account_id,
        })?;

    Ok(ProgramOutput::new(
        NATIVE_TOKEN_PROGRAM_ID,
        caller_account_id,
        instruction_data.clone(),
        vec![
            AccountStateDiff::new(sender.clone(), encode_balance(sent)),
            AccountStateDiff::new(recipient.clone(), encode_balance(received)),
        ],
    ))
}

/// A chained transfer out of an account the caller holds under `seed`.
#[must_use]
pub fn custody_transfer(
    from: AccountId,
    seed: PdaSeed,
    to: AccountId,
    amount: Balance,
) -> ChainedCall {
    ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::balance(from),
            ProgramShardSelector::balance(to),
        ],
        &Instruction::Transfer { amount },
    )
    .with_pda_seeds(vec![seed])
}
