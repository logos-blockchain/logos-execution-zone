use bridge_core::Instruction;
use lee_core::{
    native_token::custody_transfer,
    program::{
        LeeCall, Plan, ProgramEvent, ProgramInput, read_lee_call, resolve_keep, resolve_write,
    },
};

/// The receipt shard is the L1-deposit replay guard, so each branch of the planned deposit
/// carries the claim it depends on and the receipt itself decides whether that claim holds.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    RequireProcessed,
    RecordDeposit,
}

/// A written receipt is one marker byte; crediting the receipt's balance does not affect this.
const RECEIPT_MARKER: [u8; 1] = [1];

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => execute(input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect =
                borsh::from_slice(&input.effect_data).expect("the bridge wrote its own effect");
            match resolve_effect(&effect, &input.pre_data) {
                None => resolve_keep(input),
                Some(data) => {
                    resolve_write(input, data.try_into().expect("1 byte fits in account data"))
                }
            }
        }
    }
}

fn resolve_effect(effect: &Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::RequireProcessed => {
            assert!(
                !pre_data.is_empty(),
                "Deposit claims to be a replay but its receipt was never written"
            );
            None
        }
        Effect::RecordDeposit => {
            assert!(
                pre_data.is_empty(),
                "Deposit was already processed: its receipt is written"
            );
            Some(RECEIPT_MARKER.to_vec())
        }
    }
}

fn execute(input: ProgramInput<Instruction>, instruction_data: Vec<u8>) -> ! {
    assert!(
        input.caller_account_id.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let Instruction::Deposit {
        l1_deposit_op_id,
        recipient_id,
        amount,
        already_processed,
    } = input.instruction
    else {
        panic!("Withdraws are disabled in the current version of LEZ");
    };

    let [bridge, recipient, receipt] =
        <[_; 3]>::try_from(input.accounts.clone()).expect("Deposit requires exactly 3 accounts");

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
    // The replay branch only inspects the receipt, so nothing downstream would catch it being
    // named under some other program's shard of the same account.
    assert_eq!(
        receipt.program_account_id, input.self_account_id,
        "The deposit receipt must be named under this program's shard"
    );

    let mut plan = Plan::new(&input, instruction_data);
    if already_processed {
        // A replay mints nothing, but the receipt still has to confirm that it is one.
        plan.effect(&receipt, &Effect::RequireProcessed);
    } else {
        plan.update(&receipt, &Effect::RecordDeposit);
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
    }
    plan.write()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_deposit_writes_the_receipt() {
        assert_eq!(
            resolve_effect(&Effect::RecordDeposit, &[]),
            Some(RECEIPT_MARKER.to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "Deposit was already processed")]
    fn a_replayed_deposit_cannot_claim_to_be_the_first() {
        // The whole point: a second delivery of one `l1_deposit_op_id` proposing the
        // first-deposit branch would otherwise mint `amount` again out of bridge custody.
        resolve_effect(&Effect::RecordDeposit, &RECEIPT_MARKER);
    }

    #[test]
    fn a_replay_keeps_the_receipt_untouched() {
        assert_eq!(
            resolve_effect(&Effect::RequireProcessed, &RECEIPT_MARKER),
            None
        );
    }

    #[test]
    #[should_panic(expected = "claims to be a replay")]
    fn an_unprocessed_deposit_cannot_claim_to_be_a_replay() {
        // The other direction still has to reject: silently accepting it would turn a real,
        // unminted deposit into a no-op that nothing ever retries.
        resolve_effect(&Effect::RequireProcessed, &[]);
    }
}
