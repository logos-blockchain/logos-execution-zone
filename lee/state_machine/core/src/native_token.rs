use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    account::{AccountId, Balance, ProgramShardSelector, ShardData},
    program::{
        AccountMeta, ApplyInput, ApplyOutput, ChainedCall, InstructionData, PdaSeed, PlanInput,
        PlanOutput, ShardEffect,
    },
};

/// Hardcoded native token shard address.
pub const NATIVE_TOKEN_PROGRAM_ID: AccountId = AccountId::new([0; 32]);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    Transfer { amount: Balance },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Debit(Balance),
    Credit(Balance),
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum TransferError {
    #[error("native transfer instruction does not decode")]
    InvalidInstruction,
    #[error("native transfer takes a sender and a recipient row, both selecting the native shard")]
    InvalidInputs,
    #[error("native transfer sender {account_id} is not authorized")]
    UnauthorizedSender { account_id: AccountId },
    #[error("native effect does not decode")]
    InvalidEffect,
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

pub fn plan(
    caller_account_id: Option<AccountId>,
    accounts: &[AccountMeta],
    instruction_data: &InstructionData,
) -> Result<PlanOutput, TransferError> {
    let Ok(Instruction::Transfer { amount }) = borsh::from_slice(instruction_data) else {
        return Err(TransferError::InvalidInstruction);
    };

    let [sender, recipient] = accounts else {
        return Err(TransferError::InvalidInputs);
    };
    if sender.program_account_id != NATIVE_TOKEN_PROGRAM_ID
        || recipient.program_account_id != NATIVE_TOKEN_PROGRAM_ID
        || sender.account_id == recipient.account_id
    {
        return Err(TransferError::InvalidInputs);
    }
    if !sender.is_authorized {
        return Err(TransferError::UnauthorizedSender {
            account_id: sender.account_id,
        });
    }

    Ok(PlanOutput::new(PlanInput {
        self_account_id: NATIVE_TOKEN_PROGRAM_ID,
        caller_account_id,
        accounts: accounts.to_vec(),
        instruction_data: instruction_data.clone(),
    })
    .with_effects(vec![
        ShardEffect::new(sender, &Effect::Debit(amount)),
        ShardEffect::new(recipient, &Effect::Credit(amount)),
    ]))
}

pub fn apply(input: &ApplyInput) -> Result<ShardData, TransferError> {
    let Ok(effect) = borsh::from_slice::<Effect>(&input.effect_data) else {
        return Err(TransferError::InvalidEffect);
    };
    let account_id = input.selector.account_id;
    let balance = decode_balance(&input.pre_data)?;
    let post = match effect {
        Effect::Debit(amount) => balance
            .checked_sub(amount)
            .ok_or(TransferError::InsufficientBalance { account_id })?,
        Effect::Credit(amount) => balance
            .checked_add(amount)
            .ok_or(TransferError::BalanceOverflow { account_id })?,
    };

    Ok(encode_balance(post))
}

pub fn apply_output(input: &ApplyInput) -> Result<ApplyOutput, TransferError> {
    Ok(ApplyOutput {
        post_data: Some(apply(input)?),
        input: input.clone(),
    })
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
            ProgramShardSelector::native_balance(from),
            ProgramShardSelector::native_balance(to),
        ],
        &Instruction::Transfer { amount },
    )
    .with_pda_seeds(vec![seed])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::validate_plan;

    fn account_id(seed: u8) -> AccountId {
        AccountId::new([seed; 32])
    }

    fn handle(seed: u8, is_authorized: bool) -> AccountMeta {
        AccountMeta::native_balance(account_id(seed), is_authorized)
    }

    fn transfer(amount: Balance) -> InstructionData {
        borsh::to_vec(&Instruction::Transfer { amount }).expect("the instruction serializes")
    }

    fn apply_at(
        seed: u8,
        pre_data: ShardData,
        effect_data: Vec<u8>,
    ) -> Result<ShardData, TransferError> {
        apply(&ApplyInput {
            self_account_id: NATIVE_TOKEN_PROGRAM_ID,
            selector: ProgramShardSelector::native_balance(account_id(seed)),
            pre_data,
            effect_data,
        })
    }

    fn effect_bytes(effect: &Effect) -> Vec<u8> {
        borsh::to_vec(effect).expect("the effect serializes")
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
    fn a_transfer_plans_a_debit_and_a_credit_on_an_unauthorized_recipient() {
        let caller = account_id(9);
        let instruction = transfer(30);
        let accounts = [handle(1, true), handle(2, false)];
        let output = plan(Some(caller), &accounts, &instruction).expect("the transfer succeeds");

        let [debit, credit] = output.effects.as_slice() else {
            panic!(
                "the planner emits exactly two effects: {:?}",
                output.effects
            );
        };
        assert_eq!(
            debit.selector,
            ProgramShardSelector::native_balance(account_id(1))
        );
        assert_eq!(debit.data, effect_bytes(&Effect::Debit(30)));
        assert_eq!(
            credit.selector,
            ProgramShardSelector::native_balance(account_id(2))
        );
        assert_eq!(credit.data, effect_bytes(&Effect::Credit(30)));

        assert_eq!(output.input.accounts, accounts);
        assert!(validate_plan(&output.input, &output).is_ok());
        assert_eq!(output.input.self_account_id, NATIVE_TOKEN_PROGRAM_ID);
        assert_eq!(output.input.caller_account_id, Some(caller));
        assert_eq!(output.input.instruction_data, instruction);
        assert!(output.chained_calls.is_empty());
        assert!(output.events.is_empty());
        assert_eq!(output.block_validity_window.start(), None);
        assert_eq!(output.block_validity_window.end(), None);
        assert_eq!(output.timestamp_validity_window.start(), None);
        assert_eq!(output.timestamp_validity_window.end(), None);
    }

    #[test]
    fn a_plan_applies_as_a_conserved_transfer() {
        let output = plan(None, &[handle(1, true), handle(2, false)], &transfer(30))
            .expect("the transfer succeeds");

        let post: Vec<Balance> = output
            .effects
            .iter()
            .zip([encode_balance(100), encode_balance(5)])
            .map(|(effect, pre_data)| {
                let applied = apply(&ApplyInput {
                    self_account_id: NATIVE_TOKEN_PROGRAM_ID,
                    selector: effect.selector,
                    pre_data,
                    effect_data: effect.data.clone(),
                })
                .expect("the effect applies");
                decode_balance(&applied).expect("apply writes canonical balances")
            })
            .collect();

        assert_eq!(post, vec![70, 35]);
    }

    #[test]
    fn exact_depletion_prunes_the_sender_shard() {
        let post = apply_at(1, encode_balance(100), effect_bytes(&Effect::Debit(100)))
            .expect("the debit applies");

        assert!(post.is_empty());
        assert_eq!(decode_balance(&post), Ok(0));
    }

    #[test]
    fn a_zero_amount_leaves_both_balances() {
        assert_eq!(
            apply_at(1, encode_balance(100), effect_bytes(&Effect::Debit(0))),
            Ok(encode_balance(100))
        );
        assert_eq!(
            apply_at(2, encode_balance(5), effect_bytes(&Effect::Credit(0))),
            Ok(encode_balance(5))
        );
    }

    #[test]
    fn an_unauthorized_sender_is_rejected_even_for_a_zero_amount() {
        for amount in [0, 30] {
            assert_eq!(
                plan(
                    None,
                    &[handle(1, false), handle(2, false)],
                    &transfer(amount)
                ),
                Err(TransferError::UnauthorizedSender {
                    account_id: account_id(1)
                })
            );
        }
    }

    #[test]
    fn a_transfer_beyond_the_senders_balance_is_rejected() {
        assert_eq!(
            apply_at(1, encode_balance(100), effect_bytes(&Effect::Debit(101))),
            Err(TransferError::InsufficientBalance {
                account_id: account_id(1)
            })
        );
    }

    #[test]
    fn a_transfer_that_overflows_the_recipient_is_rejected() {
        assert_eq!(
            apply_at(
                2,
                encode_balance(Balance::MAX - 1),
                effect_bytes(&Effect::Credit(2))
            ),
            Err(TransferError::BalanceOverflow {
                account_id: account_id(2)
            })
        );
    }

    #[test]
    fn a_non_canonical_pre_state_is_rejected() {
        let malformed = ShardData::try_from(vec![0; 16]).expect("fits the shard limit");

        assert_eq!(
            apply_at(1, malformed, effect_bytes(&Effect::Debit(0))),
            Err(TransferError::InvalidBalance(InvalidBalanceEncoding))
        );
    }

    #[test]
    fn inputs_that_are_not_an_ordered_pair_of_native_rows_are_rejected() {
        let application_row = AccountMeta::new(account_id(1), true, account_id(7));
        let cases = vec![
            vec![],
            vec![handle(1, true)],
            vec![handle(1, true), handle(2, false), handle(3, false)],
            vec![handle(1, true), handle(1, true)],
            vec![application_row.clone(), handle(2, false)],
            vec![handle(1, true), application_row],
        ];

        for accounts in cases {
            assert_eq!(
                plan(None, &accounts, &transfer(0)),
                Err(TransferError::InvalidInputs),
                "{accounts:?} was accepted"
            );
        }
    }

    #[test]
    fn an_undecodable_instruction_is_rejected() {
        for instruction in [vec![], vec![0xFF], transfer(1)[..3].to_vec()] {
            assert_eq!(
                plan(None, &[handle(1, true), handle(2, false)], &instruction),
                Err(TransferError::InvalidInstruction)
            );
        }
    }

    #[test]
    fn an_undecodable_effect_is_rejected() {
        for effect_data in [
            vec![],
            vec![0xFF],
            effect_bytes(&Effect::Debit(1))[..3].to_vec(),
        ] {
            assert_eq!(
                apply_at(1, encode_balance(100), effect_data),
                Err(TransferError::InvalidEffect)
            );
        }
    }
}
