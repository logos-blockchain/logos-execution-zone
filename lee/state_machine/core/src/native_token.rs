use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    account::{AccountId, Actor, ActorState, Balance},
    program::{Call, PdaSeed, ReceiveInput, Response, StateReply, Transition},
};

/// Hardcoded native token program address.
pub const NATIVE_TOKEN_PROGRAM_ID: AccountId = AccountId::new([0; 32]);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Transfer { to: AccountId, amount: Balance },
    Credit(Balance),
    ReadState,
    StateReply(StateReply),
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum TransferError {
    #[error("native transfer message does not decode")]
    InvalidMessage,
    #[error("native transfer sender {account_id} is not authorized")]
    UnauthorizedSender { account_id: AccountId },
    #[error("native credit to {account_id} was not sent by a native transfer")]
    ForeignCredit { account_id: AccountId },
    #[error(transparent)]
    InvalidBalance(#[from] InvalidBalanceEncoding),
    #[error("sender {account_id} holds less than the transferred amount")]
    InsufficientBalance { account_id: AccountId },
    #[error("recipient {account_id} balance overflows")]
    BalanceOverflow { account_id: AccountId },
    #[error("native balance {account_id} consumes no state replies")]
    UnexpectedReply { account_id: AccountId },
    #[error("native balance {account_id} was read with no one to reply to")]
    UnroutableRead { account_id: AccountId },
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("native balance actor state is not a canonical encoding")]
pub struct InvalidBalanceEncoding;

#[must_use]
pub fn encode_balance(balance: Balance) -> ActorState {
    if balance == 0 {
        ActorState::empty()
    } else {
        ActorState::from(balance.to_le_bytes().to_vec())
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

pub fn handle_message(input: &ReceiveInput) -> Result<Transition, TransferError> {
    let Ok(message) = borsh::from_slice::<Message>(&input.message) else {
        return Err(TransferError::InvalidMessage);
    };
    let account_id = input.receiver.account_id;
    let response = match message {
        Message::Transfer { to, amount } => {
            debit(input, amount)?.cast(Actor::native_balance(to), &Message::Credit(amount))
        }
        Message::Credit(amount) => {
            if !input.from_own_program() {
                return Err(TransferError::ForeignCredit { account_id });
            }
            let post = decode_balance(&input.pre_state)?
                .checked_add(amount)
                .ok_or(TransferError::BalanceOverflow { account_id })?;
            Response::set_state(encode_balance(post))
        }
        Message::ReadState => {
            let reader = input
                .from
                .ok_or(TransferError::UnroutableRead { account_id })?;
            Response::keep_state().call(reader, &Message::StateReply(StateReply::from(input)))
        }
        Message::StateReply(_) => return Err(TransferError::UnexpectedReply { account_id }),
    };
    Ok(response.into_transition(input.clone()))
}

fn debit(input: &ReceiveInput, amount: Balance) -> Result<Response, TransferError> {
    let account_id = input.receiver.account_id;
    if !input.is_authorized {
        return Err(TransferError::UnauthorizedSender { account_id });
    }
    let post = decode_balance(&input.pre_state)?
        .checked_sub(amount)
        .ok_or(TransferError::InsufficientBalance { account_id })?;
    Ok(Response::set_state(encode_balance(post)))
}

/// A transfer out of an account the caller holds under `seed`.
#[must_use]
pub fn custody_transfer(from: AccountId, seed: PdaSeed, to: AccountId, amount: Balance) -> Call {
    Call::new(
        Actor::native_balance(from),
        &Message::Transfer { to, amount },
    )
    .with_pda_seeds(vec![seed])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::program::Cast;

    fn native(tag: u8) -> Actor {
        Actor::native_balance(AccountId::new([tag; 32]))
    }

    fn input(self_account: u8, authorized: bool, pre: Balance, message: &Message) -> ReceiveInput {
        ReceiveInput {
            receiver: native(self_account),
            from: None,
            is_authorized: authorized,
            pre_state: encode_balance(pre),
            message: borsh::to_vec(message).unwrap(),
        }
    }

    fn credit(
        amount: Balance,
        pre: Balance,
        from: Option<Actor>,
    ) -> Result<Transition, TransferError> {
        handle_message(&ReceiveInput {
            from,
            ..input(2, false, pre, &Message::Credit(amount))
        })
    }

    fn transfer(amount: Balance) -> Message {
        Message::Transfer {
            to: AccountId::new([2; 32]),
            amount,
        }
    }

    #[test]
    fn a_balance_round_trips_through_the_codec() {
        for balance in [1, 42, u128::from(u64::MAX), Balance::MAX] {
            assert_eq!(decode_balance(&encode_balance(balance)), Ok(balance));
        }
        assert!(encode_balance(0).is_empty());
        assert_eq!(decode_balance(&ActorState::empty()), Ok(0));
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        for bytes in [vec![0; 16], vec![1], vec![1; 15], vec![1; 17], vec![0; 32]] {
            let data = ActorState::from(bytes.clone());
            assert_eq!(
                decode_balance(&data),
                Err(InvalidBalanceEncoding),
                "{bytes:?} decoded as a balance"
            );
        }
    }

    #[test]
    fn a_transfer_debits_the_sender_and_credits_the_recipient() {
        let transition = handle_message(&input(1, true, 100, &transfer(30))).unwrap();

        assert_eq!(transition.response.post_state, Some(encode_balance(70)));
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (Vec::new(), vec![Cast::new(native(2), &Message::Credit(30))])
        );
    }

    #[test]
    fn an_unauthorized_transfer_is_rejected() {
        assert_eq!(
            handle_message(&input(1, false, 100, &transfer(30))),
            Err(TransferError::UnauthorizedSender {
                account_id: AccountId::new([1; 32])
            })
        );
    }

    #[test]
    fn a_public_origin_debits_an_account_only_with_its_authorization() {
        let from_public = |authorized| ReceiveInput {
            from: Some(native(3)),
            ..input(1, authorized, 100, &transfer(30))
        };

        assert_eq!(
            handle_message(&from_public(true))
                .unwrap()
                .response
                .post_state,
            Some(encode_balance(70))
        );
        assert_eq!(
            handle_message(&from_public(false)),
            Err(TransferError::UnauthorizedSender {
                account_id: AccountId::new([1; 32])
            })
        );
    }

    #[test]
    fn a_transfer_beyond_the_sender_balance_is_rejected() {
        assert_eq!(
            handle_message(&input(1, true, 100, &transfer(101))),
            Err(TransferError::InsufficientBalance {
                account_id: AccountId::new([1; 32])
            })
        );
    }

    #[test]
    fn a_credit_adds_to_the_balance_unless_it_overflows() {
        let from_native = Some(native(1));
        assert_eq!(
            credit(5, 100, from_native).unwrap().response.post_state,
            Some(encode_balance(105))
        );
        assert_eq!(
            credit(1, Balance::MAX, from_native),
            Err(TransferError::BalanceOverflow {
                account_id: AccountId::new([2; 32])
            })
        );
    }

    #[test]
    fn a_credit_not_sent_by_a_native_transfer_is_rejected() {
        let foreign = Err(TransferError::ForeignCredit {
            account_id: AccountId::new([2; 32]),
        });
        assert_eq!(credit(5, 100, None), foreign);
        assert_eq!(
            credit(
                5,
                100,
                Some(Actor::new(AccountId::new([1; 32]), AccountId::new([7; 32])))
            ),
            foreign
        );
    }

    #[test]
    fn a_custody_transfer_is_a_seeded_transfer_from_the_native_actor() {
        let seed = PdaSeed::new([3; 32]);

        assert_eq!(
            custody_transfer(AccountId::new([1; 32]), seed, AccountId::new([2; 32]), 7),
            Call {
                to: native(1),
                message: borsh::to_vec(&transfer(7)).unwrap(),
                pda_seeds: BTreeSet::from([seed]),
            }
        );
    }

    #[test]
    fn a_state_read_replies_with_the_readers_own_balance() {
        let reader = Actor::new(AccountId::new([9; 32]), AccountId::new([8; 32]));

        let transition = handle_message(&ReceiveInput {
            from: Some(reader),
            ..input(1, false, 100, &Message::ReadState)
        })
        .unwrap();

        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![Call::new(
                    reader,
                    &Message::StateReply(StateReply {
                        state: encode_balance(100),
                    }),
                )],
                Vec::new()
            )
        );
    }

    #[test]
    fn a_root_state_read_is_refused() {
        assert_eq!(
            handle_message(&input(1, false, 100, &Message::ReadState)),
            Err(TransferError::UnroutableRead {
                account_id: AccountId::new([1; 32])
            })
        );
    }

    #[test]
    fn a_native_balance_refuses_a_state_reply() {
        let reply = Message::StateReply(StateReply {
            state: encode_balance(100),
        });

        assert_eq!(
            handle_message(&input(1, true, 100, &reply)),
            Err(TransferError::UnexpectedReply {
                account_id: AccountId::new([1; 32])
            })
        );
    }
}
