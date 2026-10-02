use bridge_core::Message;
use lee_core::{
    native_token::custody_transfer,
    program::{ProgramEvent, ReceiveInput, Response, SendMode, run_actor},
};

/// A written receipt is one marker byte; crediting the receipt's balance does not affect this.
const RECEIPT_MARKER: [u8; 1] = [1];

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
    assert!(
        input.origin.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let Message::Deposit {
        l1_deposit_op_id,
        recipient_id,
        amount,
    } = message
    else {
        panic!("Withdraws are disabled in the current version of LEZ");
    };

    let bridge = input.receiver.program_account_id;
    // The receipt shard is the L1-deposit replay guard, so it must be the one this op id derives.
    assert_eq!(
        input.receiver.account_id,
        bridge_core::deposit_receipt_account_id(bridge, l1_deposit_op_id),
        "the receiver must be the deposit-receipt PDA"
    );
    assert!(
        input.pre_state.is_empty(),
        "Deposit was already processed: its receipt is written"
    );

    Response::write(RECEIPT_MARKER.to_vec())
        .send(custody_transfer(
            bridge_core::compute_bridge_account_id(bridge),
            bridge_core::compute_bridge_seed(),
            recipient_id,
            u128::from(amount),
            SendMode::Call,
        ))
        .event(ProgramEvent {
            selector: bridge_core::event::Deposit::SELECTOR,
            data: bridge_core::event::Deposit {
                l1_deposit_op_id,
                recipient_id,
                amount,
            }
            .to_bytes(),
        })
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, Actor, ActorState},
        program::Transition,
    };

    use super::*;

    const BRIDGE: AccountId = AccountId::new([7; 32]);
    const RECIPIENT: AccountId = AccountId::new([2; 32]);
    const OP_ID: [u8; 32] = [3; 32];

    fn deposit() -> Message {
        Message::Deposit {
            l1_deposit_op_id: OP_ID,
            recipient_id: RECIPIENT,
            amount: 5,
        }
    }

    fn run(origin: Option<AccountId>, pre: &[u8]) -> Transition {
        let receiver = Actor::new(
            bridge_core::deposit_receipt_account_id(BRIDGE, OP_ID),
            BRIDGE,
        );
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_state: ActorState::from(pre.to_vec()),
            message: borsh::to_vec(&deposit()).unwrap(),
        };
        receive(&input, deposit()).into_transition(input)
    }

    #[test]
    fn a_first_deposit_writes_the_receipt() {
        let transition = run(None, &[]);

        assert_eq!(
            transition.response.post_state,
            Some(ActorState::from(RECEIPT_MARKER.to_vec()))
        );
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![custody_transfer(
                    bridge_core::compute_bridge_account_id(BRIDGE),
                    bridge_core::compute_bridge_seed(),
                    RECIPIENT,
                    5,
                    SendMode::Call
                )],
                Vec::new()
            )
        );
        assert_eq!(transition.response.events.len(), 1);
    }

    #[test]
    #[should_panic(expected = "Deposit was already processed")]
    fn a_replayed_deposit_cannot_claim_to_be_the_first() {
        // The whole point: a second delivery of one `l1_deposit_op_id` would otherwise mint
        // `amount` again out of bridge custody.
        let _transition = run(None, &RECEIPT_MARKER);
    }

    #[test]
    #[should_panic(expected = "Bridge cannot be invoked through chain calls")]
    fn a_deposit_from_another_program_is_refused() {
        let _transition = run(Some(AccountId::new([5; 32])), &[]);
    }
}
