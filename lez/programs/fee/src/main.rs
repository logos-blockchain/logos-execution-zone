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
    program::{Call, Origin, ReadState, ReceiveInput, Response, StateReply, run_actor_with},
};

fn main() {
    run_actor_with(receive)
}

fn receive(input: &ReceiveInput) -> Response {
    assert_eq!(
        input.receiver.account_id,
        compute_fee_state_account_id(input.receiver.program_account_id),
        "Invalid fee state account"
    );
    if input.origin_program() == Some(NATIVE_TOKEN_PROGRAM_ID) {
        let NativeMessage::StateReply(reply) =
            borsh::from_slice(&input.message).expect("a native message must decode")
        else {
            panic!("The native program sends the fee program only state replies");
        };
        return pay_out(input, &reply);
    }
    assert!(
        matches!(input.origin, Origin::Root),
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
            Response::write(fee_state.to_bytes()).send(Call::new(
                Actor::native_balance(inbox),
                &NativeMessage::ReadState(ReadState {
                    reply_to: input.receiver,
                }),
            ))
        }
        Message::Refund { amount, payer } => {
            Response::keep().send(custody_transfer(inbox, fee_inbox_seed(), payer, amount))
        }
    }
}

fn pay_out(input: &ReceiveInput, reply: &StateReply) -> Response {
    let fee_account_id = input.receiver.program_account_id;
    let inbox = compute_fee_inbox_account_id(fee_account_id);
    assert_eq!(
        reply.subject,
        Actor::native_balance(inbox),
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
        Response::write(fee_state.to_bytes()),
        |response, (from, seed, to, amount)| {
            response.send(custody_transfer(from, seed, to, amount))
        },
    )
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use lee_core::{
        account::{AccountId, ActorState, Balance},
        native_token::encode_balance,
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

    fn run(
        account_id: AccountId,
        origin: Origin,
        pre: Vec<u8>,
        message: &impl BorshSerialize,
    ) -> Transition {
        let receiver = Actor::new(account_id, FEE);
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_state: ActorState::try_from(pre).unwrap(),
            message: borsh::to_vec(message).unwrap(),
        };
        receive(&input).into_transition(input)
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
            &Message::Distribute {
                summary: block,
                payout,
                producer: PRODUCER,
            },
        )
    }

    // Distributes, then answers the inbox read with `inbox_balance`.
    fn pay_out_after(
        state: &FeeState,
        block: fee_core::BlockFeeSummary,
        payout: Balance,
        inbox_balance: Balance,
    ) -> Transition {
        let distributed = distribute_at(state, block, payout).response.post_state;
        run(
            compute_fee_state_account_id(FEE),
            Origin::Program(NATIVE_TOKEN_PROGRAM_ID),
            distributed
                .expect("a distribution records its pending payout")
                .to_vec(),
            &NativeMessage::StateReply(StateReply {
                subject: Actor::native_balance(compute_fee_inbox_account_id(FEE)),
                state: encode_balance(inbox_balance),
            }),
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
        expected.pending = Some(PendingDistribution {
            revenue_base: 1_000,
            revenue_tip: 7,
            payout,
            producer: PRODUCER,
        });

        let transition = distribute_at(&state, block, payout);
        assert_eq!(
            transition.response.post_state,
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

        let transition = pay_out_after(&state, block, payout, 1_007);

        let inbox = compute_fee_inbox_account_id(FEE);
        let escrow = compute_fee_escrow_account_id(FEE);
        assert_eq!(
            transition.response.sends,
            vec![
                custody_transfer(inbox, fee_inbox_seed(), escrow, 1_000).into(),
                custody_transfer(inbox, fee_inbox_seed(), PRODUCER, 7,).into(),
                custody_transfer(escrow, fee_escrow_seed(), PRODUCER, payout,).into(),
            ]
        );
    }

    #[test]
    fn a_distribution_without_tip_or_payout_sends_only_the_base_transfer() {
        let block = summary(10, 0);
        let payout = honest_payout(&FeeState::genesis(), &block);
        assert_eq!(
            payout, 0,
            "a small first-block revenue pays out nothing yet"
        );

        let transition = pay_out_after(&FeeState::genesis(), block, payout, 10);

        let inbox = compute_fee_inbox_account_id(FEE);
        let escrow = compute_fee_escrow_account_id(FEE);
        assert_eq!(
            transition.response.sends,
            vec![custody_transfer(inbox, fee_inbox_seed(), escrow, 10).into()]
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
            &Message::Refund {
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
            &Message::Refund {
                amount: 1,
                payer: PAYER,
            },
        );
    }
}
