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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::CallKind;

    fn row(seed: u8, is_authorized: bool, balance: Balance) -> AccountInput {
        AccountInput::balance(AccountId::new([seed; 32]), is_authorized, balance)
    }

    fn transfer(amount: Balance) -> InstructionData {
        borsh::to_vec(&Instruction::Transfer { amount }).expect("the instruction serializes")
    }

    fn post_balances(output: &ProgramOutput) -> Vec<Balance> {
        output
            .state_diffs
            .iter()
            .map(|diff| {
                decode_balance(
                    diff.post_data
                        .as_ref()
                        .expect("the handler writes both rows"),
                )
                .expect("the handler writes canonical balances")
            })
            .collect()
    }

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

    #[test]
    fn a_transfer_moves_the_amount_to_an_unauthorized_recipient() {
        let caller = AccountId::new([9; 32]);
        let instruction = transfer(30);
        let output = execute(
            Some(caller),
            &[row(1, true, 100), row(2, false, 5)],
            &instruction,
        )
        .expect("the transfer succeeds");

        assert_eq!(post_balances(&output), vec![70, 35]);
        assert_eq!(output.self_account_id, NATIVE_TOKEN_PROGRAM_ID);
        assert_eq!(output.caller_account_id, Some(caller));
        assert_eq!(output.call_kind, CallKind::Execute);
        assert_eq!(output.instruction_data, instruction);
        assert!(output.chained_calls.is_empty());
        assert!(output.events.is_empty());
        assert_eq!(output.block_validity_window.start(), None);
        assert_eq!(output.block_validity_window.end(), None);
        assert_eq!(output.timestamp_validity_window.start(), None);
        assert_eq!(output.timestamp_validity_window.end(), None);
    }

    #[test]
    fn exact_depletion_prunes_the_sender_shard() {
        let output = execute(None, &[row(1, true, 100), row(2, false, 0)], &transfer(100))
            .expect("the transfer succeeds");

        assert!(
            output.state_diffs[0]
                .post_data
                .as_ref()
                .expect("the sender row is written")
                .is_empty()
        );
        assert_eq!(post_balances(&output), vec![0, 100]);
    }

    #[test]
    fn a_zero_amount_leaves_both_balances() {
        let output = execute(None, &[row(1, true, 100), row(2, false, 5)], &transfer(0))
            .expect("the transfer succeeds");

        assert_eq!(post_balances(&output), vec![100, 5]);
    }

    #[test]
    fn an_unauthorized_sender_is_rejected_even_for_a_zero_amount() {
        for amount in [0, 30] {
            assert_eq!(
                execute(
                    None,
                    &[row(1, false, 100), row(2, false, 0)],
                    &transfer(amount)
                ),
                Err(TransferError::UnauthorizedSender {
                    account_id: AccountId::new([1; 32])
                })
            );
        }
    }

    #[test]
    fn a_transfer_beyond_the_senders_balance_is_rejected() {
        assert_eq!(
            execute(None, &[row(1, true, 100), row(2, false, 0)], &transfer(101)),
            Err(TransferError::InsufficientBalance {
                account_id: AccountId::new([1; 32])
            })
        );
    }

    #[test]
    fn a_transfer_that_overflows_the_recipient_is_rejected() {
        assert_eq!(
            execute(
                None,
                &[row(1, true, 2), row(2, false, Balance::MAX - 1)],
                &transfer(2)
            ),
            Err(TransferError::BalanceOverflow {
                account_id: AccountId::new([2; 32])
            })
        );
    }

    #[test]
    fn a_non_canonical_pre_state_is_rejected() {
        let malformed = AccountInput::with_shard(
            AccountId::new([1; 32]),
            true,
            NATIVE_TOKEN_PROGRAM_ID,
            ShardData::try_from(vec![0; 16]).expect("fits the shard limit"),
        );

        assert_eq!(
            execute(None, &[malformed, row(2, false, 0)], &transfer(0)),
            Err(TransferError::InvalidBalance(InvalidBalanceEncoding))
        );
    }

    #[test]
    fn inputs_that_are_not_an_ordered_pair_of_native_rows_are_rejected() {
        let application_row = AccountInput::with_shard(
            AccountId::new([1; 32]),
            true,
            AccountId::new([7; 32]),
            ShardData::empty(),
        );
        let cases = vec![
            vec![],
            vec![row(1, true, 100)],
            vec![row(1, true, 100), row(2, false, 0), row(3, false, 0)],
            vec![row(1, true, 100), row(1, true, 100)],
            vec![application_row.clone(), row(2, false, 0)],
            vec![row(1, true, 100), application_row],
        ];

        for pre_states in cases {
            assert_eq!(
                execute(None, &pre_states, &transfer(0)),
                Err(TransferError::InvalidInputs),
                "{pre_states:?} was accepted"
            );
        }
    }

    #[test]
    fn an_undecodable_instruction_is_rejected() {
        for instruction in [vec![], vec![0xFF], transfer(1)[..3].to_vec()] {
            assert_eq!(
                execute(None, &[row(1, true, 100), row(2, false, 0)], &instruction),
                Err(TransferError::InvalidInstruction)
            );
        }
    }
}
