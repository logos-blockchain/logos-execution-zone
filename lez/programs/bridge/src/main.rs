use bridge_core::Instruction;
use lee_core::{
    account::Account,
    program::{ChainedCall, ProgramEvent, ProgramInput, ProgramOutput, read_lee_inputs},
};

include!("../../authenticated_transfer/image_id.rs");

fn unchanged_post_states(pre_states: &[lee_core::account::AccountWithMetadata]) -> Vec<Account> {
    pre_states
        .iter()
        .map(|pre_state| pre_state.account.clone())
        .collect()
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let pre_states_clone = pre_states.clone();

    let (post_states, chained_calls, events) = match instruction {
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
                bridge_core::compute_bridge_account_id(self_program_id),
                "First account must be bridge PDA"
            );

            assert_eq!(
                recipient.account_id, recipient_id,
                "Second account must be the recipient"
            );

            assert_eq!(
                receipt.account_id,
                bridge_core::deposit_receipt_account_id(self_program_id, l1_deposit_op_id),
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
            if receipt.account.program_owner == self_program_id.into() {
                (unchanged_post_states(&pre_states_clone), vec![], vec![])
            } else {
                // First mint: write the marker byte into the receipt. The write
                // is what records the mint -- it also makes this program the
                // receipt's owner, which is the predicate above. The contents
                // beyond "non-empty" are never read.
                let mut receipt_post = receipt.account;
                receipt_post.data = vec![1].try_into().expect("1 byte fits in account data");

                let post_states = vec![
                    bridge.account.clone(),
                    recipient.account.clone(),
                    receipt_post,
                ];

                let mut bridge_for_transfer = bridge;
                bridge_for_transfer.is_authorized = true;
                let chained_calls = vec![
                    ChainedCall::new(
                        AUTHENTICATED_TRANSFER_IMAGE_ID,
                        vec![bridge_for_transfer, recipient],
                        &authenticated_transfer_core::Instruction::Transfer {
                            amount: u128::from(amount),
                        },
                    )
                    .with_pda_seeds(vec![bridge_core::compute_bridge_seed()]),
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

                (post_states, chained_calls, events)
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
            //     bridge_core::compute_bridge_account_id(self_program_id),
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
            // (unchanged_post_states(&pre_states_clone), chained_calls, events)
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states_clone,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .with_events(events)
    .write();
}
