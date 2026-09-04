use authenticated_transfer_core::custody_transfer;
use bridge_core::Instruction;
use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramEvent, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

fn unchanged_diffs(pre_states: &[lee_core::account::AccountWithMetadata]) -> Vec<AccountStateDiff> {
    pre_states
        .iter()
        .map(|pre_state| AccountStateDiff::unchanged(pre_state.clone()))
        .collect()
}

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

    let pre_states_clone = pre_states.clone();

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

            // Replay protection: this op id was already minted iff we own the
            // receipt PDA. Ownership, not non-defaultness, is the test: anyone
            // may credit balance to the receipt address, and a bare credit must
            // not be able to make a deposit look already-minted and silently
            // skip it. A credit leaves the receipt unowned, so the mint below
            // still runs and the marker write claims it.
            //
            // Observability note: a no-op replay and a real first mint are both
            // successful txs, so an indexer cannot tell "credited here" from
            // "already credited by a peer" without deriving the receipt id and
            // checking its owner before this block — the receipt is the only
            // on-chain signal. Relevant once the explorer surfaces deposits.
            // TODO(squatting): the receipt address is derivable from the op id
            // alone. A program that writes data to it before this mint owns it,
            // and the marker write below then fails for ever — the deposit
            // bricks loudly rather than being silently skipped, and the
            // sequencer keeps re-driving the mint every block (see the deposit
            // drain). Accepted: there is no reclaim path today.
            if receipt.account.program_owner == self_account_id {
                (unchanged_diffs(&pre_states_clone), vec![], vec![])
            } else {
                // First mint: write the marker byte into the receipt. The write
                // is what records the mint.
                let receipt_post = AccountStateDiff::new(
                    receipt,
                    BalanceDiff::Add(0),
                    vec![1].try_into().expect("1 byte fits in account data"),
                );

                let post_diffs = vec![
                    AccountStateDiff::unchanged(bridge.clone()),
                    AccountStateDiff::unchanged(recipient.clone()),
                    receipt_post,
                ];

                let chained_calls = vec![custody_transfer(
                    bridge.account_id,
                    bridge_core::compute_bridge_seed(),
                    recipient.account_id,
                    u128::from(amount),
                )];

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

            // let [sender, bridge] = pre_states
            //     .try_into()
            //     .expect("Withdraw requires exactly 2 accounts");

            // assert_eq!(
            //     bridge.account_id,
            //     bridge_core::compute_bridge_account_id(self_account_id),
            //     "Second account must be bridge PDA"
            // );

            // let auth_transfer_program_id = bridge.account.program_owner;
            // assert_eq!(
            //     sender.account.program_owner, auth_transfer_program_id,
            //     "Sender account must be owned by the authenticated transfer program"
            // );

            // let events = vec![ProgramEvent {
            //     selector: bridge_core::event::Withdraw::SELECTOR,
            //     data: bridge_core::event::Withdraw {
            //         sender_id: sender.account_id,
            //         amount,
            //         bedrock_account_pk,
            //     }
            //     .to_bytes(),
            // }];

            // let chained_calls = vec![ChainedCall::new(
            //     auth_transfer_program_id,
            //     vec![sender, bridge],
            //     &authenticated_transfer_core::Instruction::Transfer {
            //         amount: u128::from(amount),
            //     },
            // )];
            // (unchanged_diffs(&pre_states_clone), chained_calls, events)
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
