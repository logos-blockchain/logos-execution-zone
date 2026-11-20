use bridge_core::{BridgeAmount, Message};
use lee_core::{
    account::{AccountId, Actor},
    native_token::{self, custody_transfer},
    program::{ProgramEvent, ReceiveInput, Response},
};

/// A written receipt is one marker byte; crediting the receipt's balance does not affect this.
const RECEIPT_MARKER: [u8; 1] = [1];

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    assert!(
        input.from.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    match message {
        Message::Deposit {
            l1_deposit_op_id,
            recipient_id,
            amount,
        } => deposit(input, l1_deposit_op_id, recipient_id, amount),
        Message::Withdraw {
            amount,
            bedrock_account_pk,
        } => withdraw(input, amount, bedrock_account_pk),
    }
}

fn deposit(
    input: &ReceiveInput,
    l1_deposit_op_id: [u8; 32],
    recipient_id: AccountId,
    amount: BridgeAmount,
) -> Response {
    let bridge = input.receiver.program_account_id;
    // The receipt actor state is the L1-deposit replay guard, so it must be the one this op id
    // derives.
    assert_eq!(
        input.receiver.account_id,
        bridge_core::deposit_receipt_account_id(bridge, l1_deposit_op_id),
        "the receiver must be the deposit-receipt PDA"
    );
    assert!(
        input.pre_state.is_empty(),
        "Deposit was already processed: its receipt is written"
    );

    Response::set_state(RECEIPT_MARKER.to_vec())
        .send(custody_transfer(
            bridge_core::compute_bridge_account_id(bridge),
            bridge_core::compute_bridge_seed(),
            recipient_id,
            u128::from(amount),
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

/// Returns `amount` from the signing account to bridge custody.
/// The event is what the sequencer pays out on L1.
fn withdraw(input: &ReceiveInput, amount: BridgeAmount, bedrock_account_pk: [u8; 32]) -> Response {
    assert!(input.is_authorized, "must sign for the withdrawing account");
    assert!(amount > 0, "a withdrawal moves a nonzero amount");

    let sender_id = input.receiver.account_id;
    Response::keep_state()
        .send_sync(
            Actor::native_balance(sender_id),
            &native_token::Message::Transfer {
                to: bridge_core::compute_bridge_account_id(input.receiver.program_account_id),
                amount: u128::from(amount),
            },
        )
        .event(ProgramEvent {
            selector: bridge_core::event::Withdraw::SELECTOR,
            data: bridge_core::event::Withdraw {
                sender_id,
                amount,
                bedrock_account_pk,
            }
            .to_bytes(),
        })
}

#[cfg(test)]
mod tests {
    use lee_core::{account::ActorState, program::Transition};

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
            from: origin.map(|sender| Actor::new(sender, sender)),
            is_authorized: false,
            pre_state: ActorState::from(pre.to_vec()),
            message: borsh::to_vec(&deposit()).unwrap(),
        };
        handle_message(&input, deposit()).into_transition(input)
    }

    #[test]
    fn a_first_deposit_writes_the_receipt() {
        let transition = run(None, &[]);

        assert_eq!(
            transition.response.post_state,
            Some(ActorState::from(RECEIPT_MARKER.to_vec()))
        );
        assert_eq!(
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
            (
                vec![custody_transfer(
                    bridge_core::compute_bridge_account_id(BRIDGE),
                    bridge_core::compute_bridge_seed(),
                    RECIPIENT,
                    5
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

    fn run_withdraw(is_authorized: bool, amount: BridgeAmount) -> Transition {
        let message = || Message::Withdraw {
            amount,
            bedrock_account_pk: [4; 32],
        };
        let input = ReceiveInput {
            receiver: Actor::new(RECIPIENT, BRIDGE),
            from: None,
            is_authorized,
            pre_state: ActorState::empty(),
            message: borsh::to_vec(&message()).unwrap(),
        };
        handle_message(&input, message()).into_transition(input)
    }

    #[test]
    fn a_withdrawal_returns_the_amount_to_custody_and_names_the_payout() {
        let transition = run_withdraw(true, 5);

        assert_eq!(transition.response.post_state, None);
        assert_eq!(transition.response.sync_messages.len(), 1);
        assert_eq!(
            transition.response.sync_messages[0].to,
            Actor::native_balance(RECIPIENT)
        );
        assert_eq!(
            bridge_core::event::Withdraw::from_bytes(&transition.response.events[0].data).unwrap(),
            bridge_core::event::Withdraw {
                sender_id: RECIPIENT,
                amount: 5,
                bedrock_account_pk: [4; 32],
            }
        );
    }

    #[test]
    #[should_panic(expected = "must sign for the withdrawing account")]
    fn a_withdrawal_nobody_signed_is_refused() {
        let _transition = run_withdraw(false, 5);
    }

    #[test]
    #[should_panic(expected = "a withdrawal moves a nonzero amount")]
    fn an_empty_withdrawal_is_refused() {
        let _transition = run_withdraw(true, 0);
    }
}
