use fee_core::{
    Message, compute_fee_escrow_account_id, compute_fee_inbox_account_id,
    compute_fee_state_account_id, fee_escrow_seed, fee_inbox_seed, market, state::FeeState,
};
use lee_core::{
    account::Actor,
    native_token::{Message as NativeMessage, custody_transfer},
    program::{Call, Origin, ReceiveInput, Response, run_actor},
};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
    assert!(
        matches!(input.origin, Origin::Root),
        "Fee program is only invoked as a top-level system transaction"
    );
    assert_eq!(
        input.receiver.account_id,
        compute_fee_state_account_id(input.receiver.program_account_id),
        "Invalid fee state account"
    );
    let fee_account_id = input.receiver.program_account_id;
    let inbox = compute_fee_inbox_account_id(fee_account_id);

    match message {
        Message::Distribute {
            summary,
            payout,
            producer,
        } => {
            if summary.gas_used_exec > market::MAX_GAS_EXEC
                || summary.gas_used_stor > market::MAX_GAS_STOR
            {
                panic!("Block fee summary exceeds per-block gas caps");
            }
            let total_revenue = summary
                .revenue_base
                .checked_add(summary.revenue_tip)
                .expect("block revenue fits u128");

            let mut fee_state = FeeState::from_bytes(&input.pre_state);
            assert_eq!(
                fee_state.apply_block(&summary),
                payout,
                "payout must be the one this block's market update produces"
            );

            let escrow = compute_fee_escrow_account_id(fee_account_id);
            // Order matters: the escrow receives the base before it pays out of it.
            let mut response = Response::write(fee_state.to_bytes()).send(
                Call::new(
                    Actor::native_balance(inbox),
                    &NativeMessage::Transfer {
                        to: escrow,
                        amount: summary.revenue_base,
                        expect_balance: Some(total_revenue),
                    },
                )
                .with_pda_seeds(vec![fee_inbox_seed()]),
            );
            if summary.revenue_tip > 0 {
                response = response.send(custody_transfer(
                    inbox,
                    fee_inbox_seed(),
                    producer,
                    summary.revenue_tip,
                ));
            }
            if payout > 0 {
                response = response.send(custody_transfer(
                    escrow,
                    fee_escrow_seed(),
                    producer,
                    payout,
                ));
            }
            response
        }
        Message::Refund { amount, payer } => {
            Response::keep().send(custody_transfer(inbox, fee_inbox_seed(), payer, amount))
        }
    }
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, ActorState, Balance},
        program::Transition,
    };

    use super::*;

    const FEE: AccountId = AccountId::new([1; 32]);
    const PRODUCER: AccountId = AccountId::new([2; 32]);
    const PAYER: AccountId = AccountId::new([3; 32]);

    fn summary(revenue_base: Balance, revenue_tip: Balance) -> fee_core::BlockFeeSummary {
        fee_core::BlockFeeSummary {
            revenue_base,
            revenue_tip,
            ..fee_core::BlockFeeSummary::default()
        }
    }

    fn warmed_state() -> FeeState {
        let mut state = FeeState::genesis();
        for _ in 0..market::SMOOTHING_WINDOW {
            state.apply_block(&summary(1_000, 0));
        }
        state
    }

    fn honest_payout(state: &FeeState, block: &fee_core::BlockFeeSummary) -> Balance {
        let mut state = state.clone();
        state.apply_block(block)
    }

    fn run(account_id: AccountId, origin: Origin, pre: Vec<u8>, message: Message) -> Transition {
        let receiver = Actor::new(account_id, FEE);
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_state: ActorState::try_from(pre).unwrap(),
            message: borsh::to_vec(&message).unwrap(),
        };
        receive(&input, message).into_transition(input)
    }

    fn distribute_at(
        state: &FeeState,
        block: fee_core::BlockFeeSummary,
        payout: Balance,
    ) -> Transition {
        run(
            compute_fee_state_account_id(FEE),
            Origin::Root,
            state.to_bytes(),
            Message::Distribute {
                summary: block,
                payout,
                producer: PRODUCER,
            },
        )
    }

    #[test]
    fn the_honest_payout_is_accepted_and_the_state_advances() {
        let state = warmed_state();
        let block = summary(1_000, 7);
        let payout = honest_payout(&state, &block);
        assert!(payout > 0, "a warmed window pays out");

        let mut expected = state.clone();
        expected.apply_block(&block);

        let transition = distribute_at(&state, block, payout);
        assert_eq!(
            transition.post_state,
            Some(ActorState::try_from(expected.to_bytes()).unwrap())
        );
    }

    #[test]
    #[should_panic(expected = "payout must be the one this block's market update produces")]
    fn an_inflated_payout_is_refused() {
        let state = warmed_state();
        let block = summary(1_000, 0);
        let payout = honest_payout(&state, &block)
            .checked_add(1)
            .expect("payout fits");
        let _transition = distribute_at(&state, block, payout);
    }

    #[test]
    #[should_panic(expected = "payout must be the one this block's market update produces")]
    fn a_payout_computed_from_a_forged_history_is_refused() {
        let mut forged = warmed_state();
        forged.apply_block(&summary(10_000_000, 0));
        let block = summary(0, 0);
        let payout = honest_payout(&forged, &block);
        let _transition = distribute_at(&FeeState::genesis(), block, payout);
    }

    #[test]
    #[should_panic(expected = "exceeds per-block gas caps")]
    fn a_summary_over_the_gas_cap_is_refused() {
        let block = fee_core::BlockFeeSummary {
            gas_used_exec: market::MAX_GAS_EXEC + 1,
            ..fee_core::BlockFeeSummary::default()
        };
        let _transition = distribute_at(&FeeState::genesis(), block, 0);
    }

    #[test]
    fn a_distribution_with_tip_and_payout_sends_all_three_transfers_in_order() {
        let state = warmed_state();
        let block = summary(1_000, 7);
        let payout = honest_payout(&state, &block);
        assert!(payout > 0, "a warmed window pays out");

        let transition = distribute_at(&state, block, payout);

        let inbox = compute_fee_inbox_account_id(FEE);
        let escrow = compute_fee_escrow_account_id(FEE);
        assert_eq!(
            transition.sends,
            vec![
                Call::new(
                    Actor::native_balance(inbox),
                    &NativeMessage::Transfer {
                        to: escrow,
                        amount: 1_000,
                        expect_balance: Some(1_007),
                    },
                )
                .with_pda_seeds(vec![fee_inbox_seed()])
                .into(),
                custody_transfer(inbox, fee_inbox_seed(), PRODUCER, 7,).into(),
                custody_transfer(escrow, fee_escrow_seed(), PRODUCER, payout,).into(),
            ]
        );
    }

    #[test]
    fn a_distribution_without_tip_or_payout_sends_only_the_pinned_inbox_transfer() {
        let block = summary(10, 0);
        let payout = honest_payout(&FeeState::genesis(), &block);
        assert_eq!(
            payout, 0,
            "a small first-block revenue pays out nothing yet"
        );

        let transition = distribute_at(&FeeState::genesis(), block, payout);

        let inbox = compute_fee_inbox_account_id(FEE);
        let escrow = compute_fee_escrow_account_id(FEE);
        assert_eq!(
            transition.sends,
            vec![
                Call::new(
                    Actor::native_balance(inbox),
                    &NativeMessage::Transfer {
                        to: escrow,
                        amount: 10,
                        expect_balance: Some(10),
                    },
                )
                .with_pda_seeds(vec![fee_inbox_seed()])
                .into(),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Fee program is only invoked as a top-level system transaction")]
    fn a_non_root_origin_is_refused() {
        let sender = Origin::Program(AccountId::new([8; 32]));
        let _transition = run(
            compute_fee_state_account_id(FEE),
            sender,
            FeeState::genesis().to_bytes(),
            Message::Refund {
                amount: 1,
                payer: PAYER,
            },
        );
    }

    #[test]
    #[should_panic(expected = "Invalid fee state account")]
    fn a_wrong_receiver_is_refused() {
        let _transition = run(
            AccountId::new([99; 32]),
            Origin::Root,
            FeeState::genesis().to_bytes(),
            Message::Refund {
                amount: 1,
                payer: PAYER,
            },
        );
    }
}
