use cross_zone_inbox_core::{
    CrossZoneMessage, Delivery, InboxConfig, Message, SeenShard, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response, write_once},
};

lee_core::define_actor_logic!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    match message {
        Message::Dispatch(msg) => {
            assert_root_origin_at_config(input);
            dispatch(input, msg)
        }
        Message::Mark(msg) => mark(input, msg),
        // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
        // a written config must already hold exactly this.
        Message::InitConfig(config) => {
            assert_root_origin_at_config(input);
            Response::set_state(write_once(&input.pre_state, config.to_bytes()))
        }
    }
}

/// Delivers a finalized peer message to its target program, refusing a replay.
///
/// The inbox does not decide who may deliver what. It authenticates transport
/// and nothing else: any program this zone hosts can be named as a target, and
/// receives a `Delivery` at its own program account's actor carrying a payload the
/// peer chose. So a program meant to be reachable across zones MUST check the
/// delivery's origin and source against sources it authorized itself, the way
/// `wrapped_token` and `ping_receiver` do. A program not meant to be reachable
/// has only whatever its own code happens to do with such a message. None of that
/// was written with cross-zone delivery in mind. User-deployed programs are
/// reachable too, and were written with no expectation of an inbox sender at all.
fn dispatch(input: &ReceiveInput, msg: CrossZoneMessage) -> Response {
    assert!(
        msg.l1_inclusion_witness.is_none(),
        "l1_inclusion_witness must be None in v1"
    );
    let cfg = InboxConfig::from_bytes(&input.pre_state).expect("inbox config decodes");
    assert!(
        msg.src_zone != cfg.self_zone,
        "Source zone must not be this zone"
    );

    let inbox = input.receiver.program_account_id;
    let seen = Actor::new(
        inbox_seen_shard_account_id(inbox, &msg.src_zone, msg.src_block_id),
        inbox,
    );
    Response::keep_state().call(seen, &Message::Mark(msg))
}

fn mark(input: &ReceiveInput, msg: CrossZoneMessage) -> Response {
    assert!(
        input.from_own_program(),
        "A delivery is only marked by the inbox's own dispatch"
    );
    assert_eq!(
        input.receiver.account_id,
        inbox_seen_shard_account_id(
            input.receiver.program_account_id,
            &msg.src_zone,
            msg.src_block_id
        ),
        "A delivery is marked only at its own seen shard"
    );
    let mut shard = SeenShard::from_bytes(&input.pre_state).expect("seen shard decodes");
    // One block id, one delivering block. The address binds the zone and block id but
    // not which block claimed them, so an equivocating peer's two blocks at one id land
    // here; the first binds the shard and the second aborts.
    assert!(
        shard.binds(&msg.src_block_hash),
        "Seen shard is bound to a different peer block at this block id"
    );
    assert!(
        !shard.contains(msg.src_tx_index),
        "This delivery is already recorded"
    );
    shard.insert(msg.src_block_hash, msg.src_tx_index);

    let target = Actor::new(msg.target_account_id, msg.target_account_id);
    Response::set_state(shard.to_bytes()).call(
        target,
        &Delivery {
            src_zone: msg.src_zone,
            src_account_id: msg.src_account_id,
            payload: msg.payload,
        },
    )
}

fn assert_root_origin_at_config(input: &ReceiveInput) {
    assert!(
        input.from.is_none(),
        "Inbox is only invoked as a top-level sequencer-origin transaction"
    );
    assert_eq!(
        input.receiver.account_id,
        inbox_config_account_id(input.receiver.program_account_id),
        "the receiver must be the inbox config PDA"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 32] = [1; 32];
    const OTHER_HASH: [u8; 32] = [2; 32];

    fn shard_with(indices: &[u32]) -> Vec<u8> {
        let mut shard = SeenShard::default();
        for index in indices {
            shard.insert(HASH, *index);
        }
        shard.to_bytes()
    }

    fn mark(src_tx_index: u32) -> Effect {
        Effect::MarkDelivery {
            src_block_hash: HASH,
            src_tx_index,
        }
    }

    #[test]
    fn a_first_delivery_is_recorded() {
        assert_eq!(apply(mark(3), &[]), Some(shard_with(&[3])));
        assert_eq!(apply(mark(4), &shard_with(&[3])), Some(shard_with(&[3, 4])));
    }

    #[test]
    #[should_panic(expected = "This delivery is already recorded")]
    fn a_recorded_delivery_cannot_claim_to_be_the_first() {
        // The replay amplifier: taken, this re-fires the target's chained call for a message
        // the zone already delivered.
        apply(mark(3), &shard_with(&[3]));
    }

    #[test]
    #[should_panic(expected = "bound to a different peer block")]
    fn a_second_block_at_one_block_id_cannot_mark_a_delivery() {
        apply(
            Effect::MarkDelivery {
                src_block_hash: OTHER_HASH,
                src_tx_index: 5,
            },
            &shard_with(&[3]),
        );
    }

    #[test]
    fn a_message_from_a_peer_zone_is_accepted() {
        let config = InboxConfig { self_zone: [9; 32] };
        assert_eq!(
            apply(Effect::ForeignZone([7; 32]), &config.to_bytes()),
            None
        );
    }

    #[test]
    #[should_panic(expected = "Source zone must not be this zone")]
    fn a_message_this_zone_addressed_to_itself_is_refused() {
        let config = InboxConfig { self_zone: [9; 32] };
        apply(Effect::ForeignZone([9; 32]), &config.to_bytes());
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        let config = InboxConfig { self_zone: [9; 32] };
        apply(
            Effect::InitConfig(InboxConfig { self_zone: [8; 32] }),
            &config.to_bytes(),
        );
    }
}
