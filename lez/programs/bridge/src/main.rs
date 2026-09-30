use bridge_core::Instruction;
use lee_core::{
    native_token::custody_transfer,
    program::{Plan, PlanInput, ProgramEvent, run_program},
};

/// The receipt shard is the L1-deposit replay guard.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    RecordDeposit,
}

/// A written receipt is one marker byte; crediting the receipt's balance does not affect this.
const RECEIPT_MARKER: [u8; 1] = [1];

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    let Effect::RecordDeposit = effect;
    assert!(
        pre_data.is_empty(),
        "Deposit was already processed: its receipt is written"
    );
    Some(RECEIPT_MARKER.to_vec())
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let Instruction::Deposit {
        l1_deposit_op_id,
        recipient_id,
        amount,
    } = instruction
    else {
        panic!("Withdraws are disabled in the current version of LEZ");
    };

    let [bridge, recipient, receipt] = <&[_; 3]>::try_from(input.accounts.as_slice())
        .expect("Deposit requires exactly 3 accounts");

    assert_eq!(
        bridge.account_id,
        bridge_core::compute_bridge_account_id(input.self_account_id),
        "First account must be bridge PDA"
    );
    assert_eq!(
        recipient.account_id, recipient_id,
        "Second account must be the recipient"
    );
    assert_eq!(
        receipt.account_id,
        bridge_core::deposit_receipt_account_id(input.self_account_id, l1_deposit_op_id),
        "Third account must be the deposit-receipt PDA"
    );

    let mut plan = Plan::new(input);
    plan.effect(receipt, &Effect::RecordDeposit);
    plan.call(custody_transfer(
        bridge.account_id,
        bridge_core::compute_bridge_seed(),
        recipient.account_id,
        u128::from(amount),
    ));
    plan.event(ProgramEvent {
        selector: bridge_core::event::Deposit::SELECTOR,
        data: bridge_core::event::Deposit {
            l1_deposit_op_id,
            recipient_id,
            amount,
        }
        .to_bytes(),
    });
    plan
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
