use fee_core::{
    Message, compute_fee_escrow_account_id, compute_fee_inbox_account_id,
    compute_fee_state_account_id, fee_escrow_seed, fee_inbox_seed, market, state::FeeState,
};
use lee_core::{
    account::Actor,
    native_token::{Message as NativeMessage, custody_transfer},
    program::{Envelope, Origin, ReceiveInput, Response, run_actor},
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

            let mut fee_state = FeeState::from_bytes(&input.pre_data);
            assert_eq!(
                fee_state.apply_block(&summary),
                payout,
                "payout must be the one this block's market update produces"
            );

            let escrow = compute_fee_escrow_account_id(fee_account_id);
            // Order matters: the escrow receives the base before it pays out of it.
            let mut response = Response::write(fee_state.to_bytes()).send(
                Envelope::new(
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
        account::{AccountId, Balance, ShardData},
        program::Transition,
    };

    use super::*;

    const FEE: AccountId = AccountId::new([1; 32]);
    const PRODUCER: AccountId = AccountId::new([2; 32]);
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
            pre_data: ShardData::try_from(pre).unwrap(),
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
            transition.post_data,
            Some(ShardData::try_from(expected.to_bytes()).unwrap())
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
}
