use fee_core::{
    BlockFeeSummary, Instruction, fee_escrow_seed, fee_inbox_seed, market, state::FeeState,
};
use lee_core::{
    account::Balance,
    native_token::{NATIVE_TOKEN_PROGRAM_ID, custody_transfer, decode_balance},
    program::{
        AccountMeta, LeeCall, Plan, ProgramInput, Proposed, read_lee_call, resolve_keep,
        resolve_write,
    },
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// The inbox belongs to the native token program, so this only inspects it.
    InboxHolds {
        revenue_base: Balance,
        revenue_tip: Balance,
    },
    ApplyBlock {
        summary: BlockFeeSummary,
        payout: Balance,
    },
}

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => execute(input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect = borsh::from_slice(&input.effect_data)
                .expect("the fee program wrote its own effect");
            match resolve_effect(&effect, &input.pre_data) {
                None => resolve_keep(input),
                Some(data) => resolve_write(
                    input,
                    data.try_into()
                        .expect("FeeState data should fit in account data"),
                ),
            }
        }
    }
}

fn resolve_effect(effect: &Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::InboxHolds {
            revenue_base,
            revenue_tip,
        } => {
            let claimed = revenue_base
                .checked_add(*revenue_tip)
                .expect("block revenue fits u128");
            let collected =
                decode_balance(pre_data).expect("the inbox selects its native balance shard");
            assert_eq!(
                collected, claimed,
                "inbox balance must equal the block's revenue"
            );
            None
        }
        Effect::ApplyBlock { summary, payout } => {
            let mut fee_state = FeeState::from_bytes(pre_data);
            assert_eq!(
                fee_state.apply_block(summary),
                *payout,
                "payout must be the one this block's market update produces"
            );
            Some(fee_state.to_bytes())
        }
    }
}

/// Every balance leaves a fee PDA through a chained authenticated transfer the PDA's seed
/// authorizes; the fee program itself only rewrites its state account.
fn execute(input: ProgramInput<Instruction>, instruction_data: Vec<u8>) -> ! {
    assert!(
        input.caller_account_id.is_none(),
        "Fee program is only invoked as a top-level system transaction"
    );

    match input.instruction {
        Instruction::Distribute { summary, payout } => {
            distribute(&input, instruction_data, summary, payout)
        }
        Instruction::Refund { amount } => refund(&input, instruction_data, amount),
    }
}

fn distribute(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    summary: BlockFeeSummary,
    payout: Balance,
) -> ! {
    let self_account_id = input.self_account_id;
    let Ok([pre_state, pre_escrow, pre_inbox, pre_producer]) =
        <[_; 4]>::try_from(input.accounts.clone())
    else {
        panic!("Distribute requires exactly 4 accounts");
    };
    if pre_state.account_id != fee_core::compute_fee_state_account_id(self_account_id)
        || pre_escrow.account_id != fee_core::compute_fee_escrow_account_id(self_account_id)
        || pre_inbox.account_id != fee_core::compute_fee_inbox_account_id(self_account_id)
    {
        panic!("Invalid input accounts");
    }
    assert_native_shard(&pre_inbox);
    if summary.gas_used_exec > market::MAX_GAS_EXEC || summary.gas_used_stor > market::MAX_GAS_STOR
    {
        panic!("Block fee summary exceeds per-block gas caps");
    }
    summary
        .revenue_base
        .checked_add(summary.revenue_tip)
        .expect("block revenue fits u128");

    let mut plan = Plan::new(input, instruction_data);
    // Before the transfers below: they drain the inbox this measures.
    let revenue = plan.require(
        &pre_inbox,
        &Effect::InboxHolds {
            revenue_base: summary.revenue_base,
            revenue_tip: summary.revenue_tip,
        },
        Proposed::new((summary.revenue_base, summary.revenue_tip)),
    );
    let payout = plan.require(
        &pre_state,
        &Effect::ApplyBlock { summary, payout },
        Proposed::new(payout),
    );

    let (revenue_base, revenue_tip) = revenue.get();
    let inbox = pre_inbox.account_id;
    let escrow = pre_escrow.account_id;
    let producer = pre_producer.account_id;
    // Order matters: the escrow receives the base before it pays out of it.
    for (from, seed, to, amount) in [
        (inbox, fee_inbox_seed(), escrow, revenue_base),
        (inbox, fee_inbox_seed(), producer, revenue_tip),
        (escrow, fee_escrow_seed(), producer, payout.get()),
    ] {
        if amount > 0 {
            plan.call(custody_transfer(from, seed, to, amount));
        }
    }
    plan.write()
}

fn refund(input: &ProgramInput<Instruction>, instruction_data: Vec<u8>, amount: Balance) -> ! {
    let Ok([pre_inbox, pre_payer]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        panic!("Refund requires exactly 2 accounts");
    };
    assert!(
        pre_inbox.account_id == fee_core::compute_fee_inbox_account_id(input.self_account_id),
        "Invalid inbox account"
    );

    let mut plan = Plan::new(input, instruction_data);
    plan.call(custody_transfer(
        pre_inbox.account_id,
        fee_inbox_seed(),
        pre_payer.account_id,
        amount,
    ));
    plan.write()
}

/// The inbox guard reads a native balance, so the handle has to select that shard.
fn assert_native_shard(account: &AccountMeta) {
    assert_eq!(
        account.program_account_id, NATIVE_TOKEN_PROGRAM_ID,
        "the inbox must be named under its native balance shard"
    );
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

    /// The state a chain reaches after 50 blocks each collecting 1000 of base revenue: its
    /// window is full, so the next payout is no longer zero.
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
            resolve_effect(
                &Effect::ApplyBlock {
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
        // The drain this guards: `payout` is the third custody transfer's amount, escrow to
        // an attacker-chosen producer.
        let state = warmed_state();
        let block = summary(1_000, 0);
        let payout = honest_payout(&state, &block)
            .checked_add(1)
            .expect("payout fits");
        resolve_effect(
            &Effect::ApplyBlock {
                summary: block,
                payout,
            },
            &state.to_bytes(),
        );
    }

    #[test]
    #[should_panic(expected = "payout must be the one this block's market update produces")]
    fn a_payout_computed_from_a_forged_history_is_refused() {
        // A payout correct for a richer window than the fee state actually holds: the
        // resolver recomputes it against the real state, so the forged history buys nothing.
        let mut forged = warmed_state();
        forged.apply_block(&summary(10_000_000, 0));
        let block = summary(0, 0);
        let payout = honest_payout(&forged, &block);
        resolve_effect(
            &Effect::ApplyBlock {
                summary: block,
                payout,
            },
            &FeeState::genesis().to_bytes(),
        );
    }

    #[test]
    fn revenue_matching_the_collected_balance_is_accepted() {
        assert_eq!(
            resolve_effect(
                &Effect::InboxHolds {
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
        // Both transfer legs are sized from this claim, so an unchecked one would pay a
        // producer out of balances the block never collected.
        resolve_effect(
            &Effect::InboxHolds {
                revenue_base: 400,
                revenue_tip: 601,
            },
            &encode_balance(1_000),
        );
    }
}
