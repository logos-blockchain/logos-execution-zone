use fee_core::{
    Message, compute_fee_escrow_account_id, compute_fee_inbox_account_id,
    compute_fee_state_account_id, fee_escrow_seed, fee_inbox_seed, market,
    state::{FeeState, PendingDistribution},
};
use lee_core::{
    account::Actor,
    native_token::{
        Message as NativeMessage, NATIVE_TOKEN_PROGRAM_ID, custody_transfer, decode_balance,
    },
    program::{ReceiveInput, Response, StateReply},
};

lee_core::define_actor_logic!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    assert_eq!(
        input.receiver.account_id,
        compute_fee_state_account_id(input.receiver.program_account_id),
        "Invalid fee state account"
    );
    if input
        .from
        .is_some_and(|from| from.program_account_id == NATIVE_TOKEN_PROGRAM_ID)
    {
        let NativeMessage::StateReply(reply) =
            borsh::from_slice(&input.message).expect("a native message must decode")
        else {
            panic!("The native program sends the fee program only state replies");
        };
        return pay_out(input, &reply);
    }
    assert!(
        input.from.is_none(),
        "Fee program is only invoked as a top-level system transaction"
    );
    let fee_account_id = input.receiver.program_account_id;
    let inbox = compute_fee_inbox_account_id(fee_account_id);

    match borsh::from_slice(&input.message).expect("a fee message must decode") {
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

            let mut fee_state = FeeState::from_bytes(&input.pre_state);
            assert_eq!(
                fee_state.apply_block(&summary),
                payout,
                "payout must be the one this block's market update produces"
            );
            fee_state.pending = Some(PendingDistribution {
                revenue_base: summary.revenue_base,
                revenue_tip: summary.revenue_tip,
                payout,
                producer,
            });
            Response::set_state(fee_state.to_bytes())
                .call(Actor::native_balance(inbox), &NativeMessage::ReadState)
        }
        Message::Refund { amount, payer } => {
            Response::keep_state().send(custody_transfer(inbox, fee_inbox_seed(), payer, amount))
        }
    }
}

fn pay_out(input: &ReceiveInput, reply: &StateReply) -> Response {
    let fee_account_id = input.receiver.program_account_id;
    let inbox = compute_fee_inbox_account_id(fee_account_id);
    assert_eq!(
        input.from,
        Some(Actor::native_balance(inbox)),
        "The reply must read the fee inbox"
    );
    let mut fee_state = FeeState::from_bytes(&input.pre_state);
    let PendingDistribution {
        revenue_base,
        revenue_tip,
        payout,
        producer,
    } = fee_state
        .pending
        .take()
        .expect("A reply must answer a pending distribution");
    assert_eq!(
        decode_balance(&reply.state).expect("the inbox holds a canonical balance"),
        revenue_base
            .checked_add(revenue_tip)
            .expect("block revenue fits u128"),
        "The inbox must hold exactly this block's revenue"
    );

    let escrow = compute_fee_escrow_account_id(fee_account_id);
    // Order matters: the escrow receives the base before it pays out of it.
    [
        (inbox, fee_inbox_seed(), escrow, revenue_base),
        (inbox, fee_inbox_seed(), producer, revenue_tip),
        (escrow, fee_escrow_seed(), producer, payout),
    ]
    .into_iter()
    .filter(|&(.., amount)| amount > 0)
    .fold(
        Response::set_state(fee_state.to_bytes()),
        |response, (from, seed, to, amount)| {
            response.send(custody_transfer(from, seed, to, amount))
        },
    )
}

#[cfg(test)]
mod tests {
    use lee_core::native_token::encode_balance;

    use super::*;

    fn summary(revenue_base: Balance, revenue_tip: Balance) -> BlockFeeSummary {
        BlockFeeSummary {
            revenue_base,
            revenue_tip,
            ..BlockFeeSummary::default()
        }
    }

    /// The state a chain reaches after 50 blocks each collecting 1000 of base revenue.
    fn warmed_state() -> FeeState {
        let mut state = FeeState::genesis();
        for _ in 0..market::SMOOTHING_WINDOW {
            state.apply_block(&summary(1_000, 0));
        }
        state
    }

    fn honest_payout(state: &FeeState, block: &BlockFeeSummary) -> Balance {
        let mut state = state.clone();
        state.apply_block(block)
    }

    #[test]
    fn the_honest_payout_is_accepted_and_the_state_advances() {
        let state = warmed_state();
        let block = summary(1_000, 7);
        let payout = honest_payout(&state, &block);
        assert!(payout > 0, "a warmed window pays out");

        let mut expected = state.clone();
        expected.apply_block(&block);
        assert_eq!(
            apply(
                Effect::ApplyBlock {
                    summary: block,
                    payout
                },
                &state.to_bytes()
            ),
            Some(expected.to_bytes())
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
        apply(
            Effect::ApplyBlock {
                summary: block,
                payout,
            },
            &state.to_bytes(),
        );
    }

    #[test]
    #[should_panic(expected = "payout must be the one this block's market update produces")]
    fn a_payout_computed_from_a_forged_history_is_refused() {
        let mut forged = warmed_state();
        forged.apply_block(&summary(10_000_000, 0));
        let block = summary(0, 0);
        let payout = honest_payout(&forged, &block);
        apply(
            Effect::ApplyBlock {
                summary: block,
                payout,
            },
            &FeeState::genesis().to_bytes(),
        );
    }

    #[test]
    fn revenue_matching_the_collected_balance_is_accepted() {
        assert_eq!(
            apply(
                Effect::InboxHolds {
                    revenue_base: 400,
                    revenue_tip: 600,
                },
                &encode_balance(1_000)
            ),
            None
        );
    }

    #[test]
    #[should_panic(expected = "inbox balance must equal the block's revenue")]
    fn revenue_beyond_what_the_inbox_collected_is_refused() {
        apply(
            Effect::InboxHolds {
                revenue_base: 400,
                revenue_tip: 601,
            },
            &encode_balance(1_000),
        );
    }
}
