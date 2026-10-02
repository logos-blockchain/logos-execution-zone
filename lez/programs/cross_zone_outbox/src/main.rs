use cross_zone_outbox_core::{Message, OutboxRecord, outbox_pda};
use lee_core::program::{ReceiveInput, Response, run_actor};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
    // The emitter, and the only identity here the state machine verifies: the driver
    // sets the origin, the sender cannot claim it. Note this is the immediate sender,
    // not the top-level program that cross-zone discovery names; the two coincide only
    // while every emitter refuses messages from another program, which both do today.
    let Some(emitter) = input.origin else {
        panic!("Outbox is only callable through a chain call from a user program");
    };

    let Message::Emit {
        target_zone,
        target_account_id,
        target_accounts,
        payload,
        ordinal,
    } = message;

    // Identity first, so a wrong account that happens to be free is reported as
    // the wrong account rather than as a used slot.
    //
    // A slot can still be denied to its intended writer by a real emission: the
    // ordinal is caller-chosen in a shard every user of an emitter shares,
    // and an emission needs no signature, so anyone can occupy one. A client must
    // pick an ordinal the chain does not already hold rather than counting from
    // zero.
    assert_eq!(
        input.receiver.account_id,
        outbox_pda(
            input.receiver.program_account_id,
            emitter,
            &target_zone,
            ordinal
        ),
        "Account must be the outbox PDA for (emitter, target_zone, ordinal)"
    );
    // A slot holds one message for ever.
    assert!(
        input.pre_state.is_empty(),
        "Outbox slot already written: one Emit per (emitter, target_zone, ordinal)"
    );

    Response::write(
        OutboxRecord {
            emitter,
            target_zone,
            ordinal,
            target_account_id,
            target_accounts,
            payload,
        }
        .to_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, Actor, ActorState},
        program::Transition,
    };

    use super::*;

    const OUTBOX: AccountId = AccountId::new([3; 32]);
    const EMITTER: AccountId = AccountId::new([4; 32]);

    fn emit() -> Message {
        Message::Emit {
            target_zone: [1; 32],
            target_account_id: AccountId::new([6; 32]),
            target_accounts: vec![],
            payload: b"payload".to_vec(),
            ordinal: 7,
        }
    }

    fn record() -> OutboxRecord {
        OutboxRecord {
            emitter: EMITTER,
            target_zone: [1; 32],
            ordinal: 7,
            target_account_id: AccountId::new([6; 32]),
            target_accounts: vec![],
            payload: b"payload".to_vec(),
        }
    }

    fn run(origin: Option<AccountId>, pre: Vec<u8>) -> Transition {
        let receiver = Actor::new(outbox_pda(OUTBOX, EMITTER, &[1; 32], 7), OUTBOX);
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_state: ActorState::from(pre),
            message: borsh::to_vec(&emit()).unwrap(),
        };
        receive(&input, emit()).into_transition(input)
    }

    #[test]
    fn an_empty_slot_takes_the_record() {
        assert_eq!(
            run(Some(EMITTER), Vec::new()).response.post_state,
            Some(ActorState::from(record().to_bytes()))
        );
    }

    #[test]
    #[should_panic(expected = "Outbox slot already written")]
    fn an_occupied_slot_refuses_a_second_message() {
        let _transition = run(Some(EMITTER), record().to_bytes());
    }

    #[test]
    #[should_panic(expected = "Outbox is only callable through a chain call from a user program")]
    fn a_root_emit_has_no_emitter_and_is_refused() {
        let _transition = run(None, Vec::new());
    }
}
