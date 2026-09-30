use cross_zone_outbox_core::Message as OutboxMessage;
use lee_core::program::{Call, Origin, ReceiveInput, Response, run_actor, write_once};
use ping_core::{SenderMessage, outbox_bytes, read_outbox, sender_config_account_id};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: SenderMessage) -> Response {
    assert!(
        matches!(input.origin, Origin::Root),
        "ping_sender is only invoked as a top-level user transaction"
    );
    assert_config_account(input);

    match message {
        SenderMessage::Send {
            outbox,
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => {
            // The outbox actor is transaction-chosen; the config is what pins its program.
            let pinned =
                read_outbox(&input.pre_data).expect("config account holds an outbox program id");
            assert_eq!(
                pinned, outbox.program_account_id,
                "the emission names a program the ping-sender config does not pin as its outbox"
            );
            Response::keep().send(Call::new(
                outbox,
                &OutboxMessage::Emit {
                    target_zone,
                    target_account_id,
                    target_accounts,
                    payload,
                    ordinal,
                },
            ))
        }
        // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
        // a written config must already pin exactly this outbox.
        SenderMessage::InitConfig { outbox_account_id } => Response::write(write_once(
            &input.pre_data,
            outbox_bytes(outbox_account_id).to_vec(),
        )),
    }
}

/// Pinned rather than caller-named: the address is what makes the config's answer this
/// program's own.
fn assert_config_account(input: &ReceiveInput) {
    assert_eq!(
        input.receiver.account_id,
        sender_config_account_id(input.receiver.program_account_id),
        "the receiver must be the ping-sender config PDA"
    );
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, Actor, ShardData},
        program::Transition,
    };

    use super::*;

    const PING_SENDER: AccountId = AccountId::new([7; 32]);
    const OUTBOX: AccountId = AccountId::new([9; 32]);

    fn run(origin: Origin, pre: &[u8], message: SenderMessage) -> Transition {
        let receiver = Actor::new(sender_config_account_id(PING_SENDER), PING_SENDER);
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_data: ShardData::try_from(pre.to_vec()).unwrap(),
            message: borsh::to_vec(&message).unwrap(),
        };
        receive(&input, message).into_transition(input)
    }

    fn send_through(outbox_program: AccountId) -> SenderMessage {
        SenderMessage::Send {
            outbox: Actor::new(AccountId::new([2; 32]), outbox_program),
            target_zone: [1; 32],
            target_account_id: AccountId::new([3; 32]),
            target_accounts: vec![],
            payload: b"ping".to_vec(),
            ordinal: 0,
        }
    }

    fn config(outbox: AccountId) -> ShardData {
        ShardData::try_from(outbox_bytes(outbox).to_vec()).unwrap()
    }

    #[test]
    fn the_pinned_outbox_is_accepted() {
        let transition = run(Origin::Root, &outbox_bytes(OUTBOX), send_through(OUTBOX));

        assert_eq!(transition.post_data, None);
        assert_eq!(
            transition.sends,
            vec![
                Call::new(
                    Actor::new(AccountId::new([2; 32]), OUTBOX),
                    &OutboxMessage::Emit {
                        target_zone: [1; 32],
                        target_account_id: AccountId::new([3; 32]),
                        target_accounts: vec![],
                        payload: b"ping".to_vec(),
                        ordinal: 0,
                    },
                )
                .into()
            ]
        );
    }

    #[test]
    #[should_panic(expected = "does not pin as its outbox")]
    fn another_program_cannot_stand_in_for_the_outbox() {
        // Unguarded this redirects the emission to an arbitrary program, which then records it,
        // or not, under its own interpretation.
        let _transition = run(
            Origin::Root,
            &outbox_bytes(OUTBOX),
            send_through(AccountId::new([1; 32])),
        );
    }

    #[test]
    fn an_empty_config_takes_the_first_init() {
        let init = SenderMessage::InitConfig {
            outbox_account_id: OUTBOX,
        };
        assert_eq!(run(Origin::Root, &[], init).post_data, Some(config(OUTBOX)));
    }

    #[test]
    fn an_identical_reinit_is_a_no_op_rewrite() {
        let init = SenderMessage::InitConfig {
            outbox_account_id: OUTBOX,
        };
        assert_eq!(
            run(Origin::Root, &outbox_bytes(OUTBOX), init).post_data,
            Some(config(OUTBOX))
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_naming_a_different_outbox_is_refused() {
        let init = SenderMessage::InitConfig {
            outbox_account_id: AccountId::new([1; 32]),
        };
        let _transition = run(Origin::Root, &outbox_bytes(OUTBOX), init);
    }

    #[test]
    #[should_panic(expected = "ping_sender is only invoked as a top-level user transaction")]
    fn a_message_from_another_program_is_refused() {
        let sender = Origin::Program(AccountId::new([6; 32]));
        let _transition = run(sender, &outbox_bytes(OUTBOX), send_through(OUTBOX));
    }
}
