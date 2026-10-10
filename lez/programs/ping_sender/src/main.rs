use cross_zone_outbox_core::Message as OutboxMessage;
use lee_core::program::{ReceiveInput, Response, write_once};
use ping_core::{SenderMessage, outbox_bytes, read_outbox, sender_config_account_id};

lee_core::define_actor_logic!(handle_message);

fn handle_message(input: &ReceiveInput, message: SenderMessage) -> Response {
    assert!(
        input.from.is_none(),
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
                read_outbox(&input.pre_state).expect("config account holds an outbox program id");
            assert_eq!(
                pinned, outbox.program_account_id,
                "the emission names a program the ping-sender config does not pin as its outbox"
            );
            Response::keep_state().call(
                outbox,
                &OutboxMessage::Emit {
                    target_zone,
                    target_account_id,
                    target_accounts,
                    payload,
                    ordinal,
                },
            )
        }
        // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
        // a written config must already pin exactly this outbox.
        SenderMessage::InitConfig { outbox_account_id } => Response::set_state(write_once(
            &input.pre_state,
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
    use super::*;

    const OUTBOX: AccountId = AccountId::new([9; 32]);

    #[test]
    fn the_pinned_outbox_is_accepted() {
        assert_eq!(apply(Effect::OutboxIs(OUTBOX), &outbox_bytes(OUTBOX)), None);
    }

    #[test]
    #[should_panic(expected = "does not pin as its outbox")]
    fn another_program_cannot_stand_in_for_the_outbox() {
        // Unguarded this redirects the emission's child call to an arbitrary program, which
        // then reads the outbox account's shard under its own interpretation.
        apply(
            Effect::OutboxIs(AccountId::new([1; 32])),
            &outbox_bytes(OUTBOX),
        );
    }

    #[test]
    fn an_empty_config_takes_the_first_init() {
        assert_eq!(
            apply(Effect::InitConfig(OUTBOX), &[]),
            Some(outbox_bytes(OUTBOX).to_vec())
        );
    }

    #[test]
    fn an_identical_reinit_is_a_no_op_rewrite() {
        assert_eq!(
            apply(Effect::InitConfig(OUTBOX), &outbox_bytes(OUTBOX)),
            Some(outbox_bytes(OUTBOX).to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_naming_a_different_outbox_is_refused() {
        apply(
            Effect::InitConfig(AccountId::new([1; 32])),
            &outbox_bytes(OUTBOX),
        );
    }
}
