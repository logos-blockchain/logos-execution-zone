use cross_zone_inbox_core::{
    CrossZoneMessage, Delivery, InboxConfig, Message, SeenShard, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use lee_core::{
    account::Actor,
    program::{Origin, ReceiveInput, Response, run_actor, write_once},
};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
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
            Response::write(write_once(&input.pre_state, config.to_bytes()))
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
    Response::keep().call(seen, &Message::Mark(msg))
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
    Response::write(shard.to_bytes()).call(
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
        matches!(input.origin, Origin::Root),
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
    use lee_core::{
        account::{AccountId, ActorState},
        program::{Call, Transition},
    };

    use super::*;

    const INBOX: AccountId = AccountId::new([5; 32]);
    const TARGET: AccountId = AccountId::new([6; 32]);
    const SOURCE: AccountId = AccountId::new([8; 32]);
    const PEER_ZONE: [u8; 32] = [7; 32];
    const SELF_ZONE: [u8; 32] = [9; 32];
    const HASH: [u8; 32] = [1; 32];
    const OTHER_HASH: [u8; 32] = [2; 32];

    fn msg(src_zone: [u8; 32], src_block_hash: [u8; 32], src_tx_index: u32) -> CrossZoneMessage {
        CrossZoneMessage {
            src_zone,
            src_block_id: 3,
            src_block_hash,
            src_tx_index,
            src_account_id: SOURCE,
            target_account_id: TARGET,
            payload: b"payload".to_vec(),
            l1_inclusion_witness: None,
        }
    }

    fn config_actor() -> Actor {
        Actor::new(inbox_config_account_id(INBOX), INBOX)
    }

    fn seen_actor() -> Actor {
        Actor::new(inbox_seen_shard_account_id(INBOX, &PEER_ZONE, 3), INBOX)
    }

    fn run(receiver: Actor, origin: Origin, pre: Vec<u8>, message: Message) -> Transition {
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_state: ActorState::try_from(pre).unwrap(),
            message: borsh::to_vec(&message).unwrap(),
        };
        receive(&input, message).into_transition(input)
    }

    fn mark_at_seen(pre: Vec<u8>, src_block_hash: [u8; 32], src_tx_index: u32) -> Transition {
        run(
            seen_actor(),
            Origin::Program(config_actor().program_account_id),
            pre,
            Message::Mark(msg(PEER_ZONE, src_block_hash, src_tx_index)),
        )
    }

    fn shard_with(indices: &[u32]) -> Vec<u8> {
        let mut shard = SeenShard::default();
        for index in indices {
            shard.insert(HASH, *index);
        }
        shard.to_bytes()
    }

    fn written(bytes: Vec<u8>) -> ActorState {
        ActorState::try_from(bytes).unwrap()
    }

    fn config() -> Vec<u8> {
        InboxConfig {
            self_zone: SELF_ZONE,
        }
        .to_bytes()
    }

    #[test]
    fn a_first_delivery_is_recorded() {
        let first = mark_at_seen(Vec::new(), HASH, 3);
        assert_eq!(first.response.post_state, Some(written(shard_with(&[3]))));
        assert_eq!(
            (first.response.calls, first.response.casts),
            (
                vec![Call::new(
                    Actor::new(TARGET, TARGET),
                    &Delivery {
                        src_zone: PEER_ZONE,
                        src_account_id: SOURCE,
                        payload: b"payload".to_vec(),
                    },
                )],
                Vec::new()
            )
        );

        assert_eq!(
            mark_at_seen(shard_with(&[3]), HASH, 4).response.post_state,
            Some(written(shard_with(&[3, 4])))
        );
    }

    #[test]
    #[should_panic(expected = "This delivery is already recorded")]
    fn a_recorded_delivery_cannot_claim_to_be_the_first() {
        // The replay amplifier: taken, this re-fires the target's delivery for a message
        // the zone already delivered.
        let _transition = mark_at_seen(shard_with(&[3]), HASH, 3);
    }

    #[test]
    #[should_panic(expected = "bound to a different peer block")]
    fn a_second_block_at_one_block_id_cannot_mark_a_delivery() {
        let _transition = mark_at_seen(shard_with(&[3]), OTHER_HASH, 5);
    }

    #[test]
    #[should_panic(expected = "A delivery is only marked by the inbox's own dispatch")]
    fn a_mark_from_outside_the_inbox_is_refused() {
        let _transition = run(
            seen_actor(),
            Origin::Root,
            Vec::new(),
            Message::Mark(msg(PEER_ZONE, HASH, 3)),
        );
    }

    // A delivery targeting the inbox program reaches `(inbox, inbox)` under the inbox's own origin.
    #[test]
    #[should_panic(expected = "A delivery is marked only at its own seen shard")]
    fn an_own_origin_mark_at_another_inbox_actor_is_refused() {
        let _transition = run(
            Actor::new(INBOX, INBOX),
            Origin::Program(seen_actor().program_account_id),
            Vec::new(),
            Message::Mark(msg(PEER_ZONE, HASH, 3)),
        );
    }

    #[test]
    fn a_message_from_a_peer_zone_is_accepted() {
        let message = msg(PEER_ZONE, HASH, 3);
        let transition = run(
            config_actor(),
            Origin::Root,
            config(),
            Message::Dispatch(message.clone()),
        );

        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![Call::new(seen_actor(), &Message::Mark(message))],
                Vec::new()
            )
        );
    }

    #[test]
    #[should_panic(expected = "Source zone must not be this zone")]
    fn a_message_this_zone_addressed_to_itself_is_refused() {
        let _transition = run(
            config_actor(),
            Origin::Root,
            config(),
            Message::Dispatch(msg(SELF_ZONE, HASH, 3)),
        );
    }

    #[test]
    #[should_panic(expected = "Inbox is only invoked as a top-level sequencer-origin transaction")]
    fn a_dispatch_from_another_program_is_refused() {
        let _transition = run(
            config_actor(),
            Origin::Program(AccountId::new([4; 32])),
            config(),
            Message::Dispatch(msg(PEER_ZONE, HASH, 3)),
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        let _transition = run(
            config_actor(),
            Origin::Root,
            config(),
            Message::InitConfig(InboxConfig { self_zone: [8; 32] }),
        );
    }
}
