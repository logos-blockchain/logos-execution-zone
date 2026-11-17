use lee_core::{
    account::Target,
    program::{AsyncMessage, ReceiveInput, Response},
};
use ping_core::SenderMessage;

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: SenderMessage) -> Response {
    assert!(
        input.from.is_none(),
        "ping_sender is only invoked as a top-level user transaction"
    );
    assert_eq!(
        input.receiver.account_id, input.receiver.program_account_id,
        "the receiver must be the ping-sender program actor"
    );

    let SenderMessage::Send {
        target_zone,
        target,
        accounts,
        payload,
    } = message;
    Response::keep_state().send(AsyncMessage {
        to: Target::Remote {
            zone: target_zone,
            actor: target,
        },
        message: payload,
        accounts,
    })
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, Actor, ActorState},
        program::Transition,
    };

    use super::*;

    const PING_SENDER: AccountId = AccountId::new([7; 32]);

    fn run(origin: Option<AccountId>, message: SenderMessage) -> Transition {
        let receiver = Actor::new(PING_SENDER, PING_SENDER);
        let input = ReceiveInput {
            receiver,
            from: origin.map(|sender| Actor::new(sender, sender).into()),
            is_authorized: false,
            pre_state: ActorState::empty(),
            message: borsh::to_vec(&message).unwrap(),
        };
        handle_message(&input, message).into_transition(input)
    }

    fn send() -> SenderMessage {
        SenderMessage::Send {
            target_zone: [1; 32],
            target: Actor::new(AccountId::new([3; 32]), AccountId::new([3; 32])),
            accounts: vec![Actor::new(AccountId::new([4; 32]), AccountId::new([3; 32]))],
            payload: b"ping".to_vec(),
        }
    }

    #[test]
    fn a_send_becomes_a_remote_async_message() {
        let transition = run(None, send());

        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            transition.response.async_messages,
            vec![AsyncMessage {
                to: Target::Remote {
                    zone: [1; 32],
                    actor: Actor::new(AccountId::new([3; 32]), AccountId::new([3; 32])),
                },
                message: b"ping".to_vec(),
                accounts: vec![Actor::new(AccountId::new([4; 32]), AccountId::new([3; 32]))],
            }]
        );
    }

    #[test]
    #[should_panic(expected = "top-level user transaction")]
    fn a_chained_send_is_refused() {
        let _transition = run(Some(AccountId::new([9; 32])), send());
    }
}
