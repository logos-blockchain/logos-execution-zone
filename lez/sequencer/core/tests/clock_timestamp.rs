#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chain_state::{Tip, apply::derive_block_summary, apply_block};
    use clock_core::{ClockAccountData, Message, Reply};
    use common::{
        block::HashableBlockData,
        test_utils::{
            produce_dummy_block, producer_account_for_testing, producer_seed, test_fee_declaration,
        },
        transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
    };
    use lee::{AccountId, Actor, PublicTransaction, public_transaction};
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    #[test]
    #[expect(
        clippy::print_stdout,
        reason = "The experiment reports the observed clock values"
    )]
    fn clock_reads_observe_the_current_block() {
        let reader_program = test_programs::clock_reader();
        let reader_program_id = AccountId::from_builtin_program(reader_program.id());
        let payer = &initial_pub_accounts_private_keys()[0];
        let reader = Actor::new(payer.account_id, reader_program_id);
        let clock = system_accounts::clock_actor();

        for message in [
            Message::ReadTimestamp { granularity: 1 },
            Message::ReadBlockId { granularity: 1 },
        ] {
            let mut state = initial_state(true)
                .with_public_accounts([producer_seed()])
                .with_programs(vec![reader_program.clone()]);
            let genesis = produce_dummy_block(1, None, vec![]);
            apply_block(None, &genesis, &mut state).expect("genesis applies");
            let mut parent = genesis;

            for id in 2..=3_u64 {
                let timestamp = id.saturating_mul(100);
                let tx_message = public_transaction::Message::try_new_with_fees(
                    reader,
                    vec![reader, clock],
                    BTreeMap::from([(
                        payer.account_id,
                        state.get_account_by_id(payer.account_id).nonce,
                    )]),
                    message,
                    test_fee_declaration(payer.account_id),
                )
                .expect("clock read message builds");
                let witnesses = public_transaction::WitnessSet::for_message(
                    &tx_message,
                    &[&payer.pub_sign_key],
                );
                let read = LeeTransaction::Public(PublicTransaction::new(tx_message, witnesses));
                let (summary, payout, reverted) =
                    derive_block_summary(&state, std::slice::from_ref(&read), id, timestamp)
                        .expect("clock read settles");
                assert!(reverted.is_empty(), "the clock read must succeed");
                let block = HashableBlockData {
                    block_id: id,
                    prev_block_hash: parent.header.hash,
                    timestamp,
                    transactions: vec![
                        LeeTransaction::Public(clock_invocation(id, timestamp)),
                        read,
                        LeeTransaction::Public(fee_invocation(
                            summary,
                            payout,
                            FeePayee::Present(producer_account_for_testing()),
                        )),
                    ],
                    reverted,
                }
                .into_pending_block();
                apply_block(Some(&Tip::from(&parent)), &block, &mut state)
                    .expect("block with a clock read applies");

                let observed = Reply::from_message(
                    state
                        .get_account_by_id(reader.account_id)
                        .data
                        .actor_state(reader_program_id),
                );
                let (parent_value, current) = match message {
                    Message::ReadTimestamp { .. } => (
                        Reply::Timestamp(parent.header.timestamp),
                        Reply::Timestamp(block.header.timestamp),
                    ),
                    Message::ReadBlockId { .. } => (
                        Reply::BlockId(parent.header.block_id),
                        Reply::BlockId(block.header.block_id),
                    ),
                    Message::Tick { .. } => unreachable!("this experiment only reads the clock"),
                };
                println!(
                    "block={id} current={current:?} parent={parent_value:?} observed={observed:?}"
                );
                assert_eq!(observed, current);
                assert_ne!(observed, parent_value);

                let stored = ClockAccountData::from_bytes(
                    state
                        .get_account_by_id(clock.account_id)
                        .data
                        .actor_state(clock.program_account_id),
                );
                assert_eq!(stored.block_id, id);
                assert_eq!(stored.timestamp, timestamp);
                parent = block;
            }
        }
    }
}
