use bridge_core::Instruction;
use lee_core::{
    account::Account,
    program::{
        AccountPostState, ChainedCall, Claim, ProgramEvent, ProgramInput, ProgramOutput,
        read_lee_inputs,
    },
};

fn unchanged_post_states(
    pre_states: &[lee_core::account::AccountWithMetadata],
) -> Vec<AccountPostState> {
    pre_states
        .iter()
        .map(|pre_state| AccountPostState::new(pre_state.account.clone()))
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
            vault_program_id,
            recipient_id,
            amount,
        } => {
            let [bridge, recipient_vault, receipt] = pre_states
                .try_into()
                .expect("Deposit requires exactly 3 accounts");

            assert_eq!(
                bridge.account_id,
                bridge_core::compute_bridge_account_id(self_program_id),
                "First account must be bridge PDA"
            );

            assert_eq!(
                recipient_vault.account_id,
                vault_core::compute_vault_account_id(vault_program_id, recipient_id),
                "Second account must be recipient vault PDA"
            );

            assert_eq!(
                receipt.account_id,
                bridge_core::deposit_receipt_account_id(self_program_id, l1_deposit_op_id),
                "Third account must be the deposit-receipt PDA"
            );

            // Replay protection: the receipt PDA exists iff this op id was
            // already minted. On replay it is non-default and the whole
            // instruction is a no-op.
            //
            // Observability note: a no-op replay and a real first mint are both
            // successful txs, so an indexer cannot tell "credited here" from
            // "already credited by a peer" without deriving the receipt id and
            // checking whether it existed before this block — the receipt claim
            // is the only on-chain signal. Relevant once the explorer surfaces
            // deposits.
            if receipt.account != Account::default() {
                (unchanged_post_states(&pre_states_clone), vec![], vec![])
            } else {
                // First mint: claim the receipt — its existence is the record,
                // the account's contents are never read — and chain the vault
                // transfer.
                let receipt_post = AccountPostState::new_claimed_if_default(
                    receipt.account,
                    Claim::Pda(bridge_core::deposit_receipt_seed(l1_deposit_op_id)),
                );

                let post_states = vec![
                    AccountPostState::new(bridge.account.clone()),
                    AccountPostState::new(recipient_vault.account.clone()),
                    receipt_post,
                ];

                let chained_calls = vec![
                    ChainedCall::new(
                        vault_program_id,
                        vec![bridge.account_id, recipient_vault.account_id],
                        &vault_core::Instruction::Transfer {
                            recipient_id,
                            amount: u128::from(amount),
                        },
                    )
                    .with_pda_seeds(vec![bridge_core::compute_bridge_seed()]),
                ];

                let events = vec![ProgramEvent {
                    selector: bridge_core::event::Deposit::SELECTOR,
                    data: bridge_core::event::Deposit {
                        l1_deposit_op_id,
                        vault_program_id,
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
