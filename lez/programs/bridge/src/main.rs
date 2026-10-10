use bridge_core::Message;
use lee_core::{
    native_token::custody_transfer,
    program::{ProgramEvent, ReceiveInput, Response},
};

/// A written receipt is one marker byte; crediting the receipt's balance does not affect this.
const RECEIPT_MARKER: [u8; 1] = [1];

lee_core::define_actor_logic!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    assert!(
        input.from.is_none(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_deposit_writes_the_receipt() {
        assert_eq!(
            apply(Effect::RecordDeposit, &[]),
            Some(RECEIPT_MARKER.to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "Deposit was already processed")]
    fn a_replayed_deposit_cannot_claim_to_be_the_first() {
        // The whole point: a second delivery of one `l1_deposit_op_id` would otherwise mint
        // `amount` again out of bridge custody.
        apply(Effect::RecordDeposit, &RECEIPT_MARKER);
    }
}
