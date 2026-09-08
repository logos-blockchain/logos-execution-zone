use authenticated_transfer_core::custody_transfer;
use bridge_core::Instruction;
use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramEvent, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    assert!(
        caller_account_id.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let (post_diffs, chained_calls, events) = match instruction {
        Instruction::Deposit {
            l1_deposit_op_id,
            recipient_id,
            amount,
        } => {
            let [bridge, recipient, receipt] = pre_states
                .try_into()
                .expect("Deposit requires exactly 3 accounts");

            assert_eq!(
                bridge.account_id,
                bridge_core::compute_bridge_account_id(self_account_id),
                "First account must be bridge PDA"
            );

            assert_eq!(
                recipient.account_id, recipient_id,
                "Second account must be the recipient"
            );

            assert_eq!(
                receipt.account_id,
                bridge_core::deposit_receipt_account_id(self_account_id, l1_deposit_op_id),
                "Third account must be the deposit-receipt PDA"
            );

            // A nonempty receipt shard marks this deposit as already processed.
            // Crediting the receipt's balance does not affect this check.
            if !receipt.shard_of(self_account_id).is_empty() {
                (
                    vec![
                        AccountStateDiff::unchanged(bridge),
                        AccountStateDiff::unchanged(recipient),
                        AccountStateDiff::unchanged(receipt),
                    ],
                    vec![],
                    vec![],
                )
            } else {
                let chained_calls = vec![custody_transfer(
                    bridge.account_id,
                    bridge_core::compute_bridge_seed(),
                    recipient.account_id,
                    u128::from(amount),
                )];

                // First mint: write the marker byte into the receipt. The write
                // is what records the mint.
                let post_diffs = vec![
                    AccountStateDiff::unchanged(bridge),
                    AccountStateDiff::unchanged(recipient),
                    AccountStateDiff::new(
                        receipt,
                        BalanceDiff::Add(0),
                        vec![1].try_into().expect("1 byte fits in account data"),
                    ),
                ];

                let events = vec![ProgramEvent {
                    selector: bridge_core::event::Deposit::SELECTOR,
                    data: bridge_core::event::Deposit {
                        l1_deposit_op_id,
                        recipient_id,
                        amount,
                    }
                    .to_bytes(),
                }];

                (post_diffs, chained_calls, events)
            }
        }
        Instruction::Withdraw {
            amount: _,
            bedrock_account_pk: _,
        } => {
            panic!("Withdraws are disabled in the current version of LEZ");
        }
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_diffs,
    )
    .with_chained_calls(chained_calls)
    .with_events(events)
    .write();
}
