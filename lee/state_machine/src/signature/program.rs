//! The native part of `signature_program`: writes an account's key state when the signature
//! program's own guest sends `SetKey`.

use lee_core::{
    program::{ReceiveInput, Response, Transition},
    signing_key::{KeyType, SignatureMessage},
};
use thiserror::Error;

use super::scheme::is_allowed_rotation_target;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKeyError {
    #[error("only the signature program may send to a signature actor")]
    ForeignSender,
    #[error("undecodable signature program message")]
    InvalidMessage,
    #[error("the next key's type may not be rotated to")]
    DisallowedRotation,
}

/// Handles a message to an account's signature actor.
pub fn handle_message(input: &ReceiveInput) -> Result<Transition, SetKeyError> {
    // The policy is a parameter so tests can refuse a type while every type is allowed.
    handle_message_with(input, is_allowed_rotation_target)
}

fn handle_message_with(
    input: &ReceiveInput,
    is_allowed: impl Fn(KeyType) -> bool,
) -> Result<Transition, SetKeyError> {
    if !input.from_own_program() {
        return Err(SetKeyError::ForeignSender);
    }
    let SignatureMessage::SetKey { next } =
        borsh::from_slice(&input.message).map_err(|_err| SetKeyError::InvalidMessage)?;
    if !is_allowed(next.key_type) {
        return Err(SetKeyError::DisallowedRotation);
    }
    Ok(Response::set_state(next).into_transition(input.clone()))
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, Actor, ActorState},
        signing_key::{SIGNATURE_PROGRAM_ID, SigningKeyState},
    };

    use super::*;

    const ACCOUNT: AccountId = AccountId::new([1; 32]);
    const FROM_THE_SIGNATURE_PROGRAM: Option<Actor> =
        Some(Actor::new(AccountId::new([9; 32]), SIGNATURE_PROGRAM_ID));

    fn key(key_type: KeyType, byte: u8) -> SigningKeyState {
        SigningKeyState {
            key_type,
            key_commitment: [byte; 32],
        }
    }

    fn set_key(next: SigningKeyState) -> Vec<u8> {
        borsh::to_vec(&SignatureMessage::SetKey { next }).unwrap()
    }

    fn input(from: Option<Actor>, message: Vec<u8>) -> ReceiveInput {
        ReceiveInput {
            receiver: Actor::new(ACCOUNT, SIGNATURE_PROGRAM_ID),
            from,
            is_authorized: false,
            pre_state: ActorState::from(key(KeyType::Wots, 2)),
            message,
        }
    }

    #[test]
    fn set_key_from_the_signature_program_sets_next() {
        let next = key(KeyType::Schnorr, 3);
        let transition = handle_message(&input(FROM_THE_SIGNATURE_PROGRAM, set_key(next))).unwrap();

        assert_eq!(transition.response.post_state, Some(ActorState::from(next)));
        assert!(transition.response.sync_messages.is_empty());
        assert!(transition.response.async_messages.is_empty());
        assert!(transition.response.events.is_empty());
    }

    #[test]
    fn a_foreign_sender_is_refused_whatever_it_sends() {
        let another_program = Some(Actor::new(AccountId::new([9; 32]), AccountId::new([8; 32])));
        for from in [None, another_program] {
            for message in [set_key(key(KeyType::Wots, 3)), vec![0xFF; 5]] {
                assert_eq!(
                    handle_message(&input(from, message)).err(),
                    Some(SetKeyError::ForeignSender)
                );
            }
        }
    }

    #[test]
    fn an_undecodable_message_from_the_signature_program_is_refused() {
        let mut trailing = set_key(key(KeyType::Wots, 3));
        trailing.push(0);
        let mut unknown_type = set_key(key(KeyType::Wots, 3));
        unknown_type[1] = 2;
        for message in [vec![0xFF; 5], unknown_type, trailing] {
            assert_eq!(
                handle_message(&input(FROM_THE_SIGNATURE_PROGRAM, message)).err(),
                Some(SetKeyError::InvalidMessage)
            );
        }
    }

    #[test]
    fn a_disallowed_type_is_refused() {
        let message = set_key(key(KeyType::Schnorr, 3));
        assert_eq!(
            handle_message_with(&input(FROM_THE_SIGNATURE_PROGRAM, message), |key_type| {
                key_type != KeyType::Schnorr
            })
            .err(),
            Some(SetKeyError::DisallowedRotation)
        );
    }
}
