use amm_core::{PoolDefinition, SwapRequest};
use lee_core::{
    account::{Actor, ActorState},
    program::{ReceiveInput, Response},
};
use token_core::Notification;

use crate::sends::withdrawal;

// Pays the live quote for the input when it meets the trader's minimum. Vault backing, not a guard
// here, keeps the paid-out reserve real: only this program can debit a vault, and every reserve
// change it records is paired with an equal transfer.
pub fn swap(input: &ReceiveInput, pool: &PoolDefinition, notification: &Notification) -> Response {
    let SwapRequest {
        definition_id_out,
        min_amount_out,
        payout,
    } = borsh::from_slice(&notification.payload)
        .expect("a swap notification must carry a swap request");
    let amount_in = notification.amount;

    assert!(amount_in != 0, "Swap amounts must be nonzero");
    // A payout that is a vault would turn the withdrawal into new funding.
    for vault in [pool.vault_a_id, pool.vault_b_id] {
        assert!(payout != vault, "A trader holding cannot be a pool vault");
    }

    assert!(pool.active, "Pool is inactive");
    let (input_side, output) = pool
        .sides(notification.descriptor.definition_id)
        .expect("AccountId is not a token type for the pool");
    assert_eq!(
        definition_id_out, output.definition_id,
        "AccountId is not a token type for the pool"
    );
    assert_eq!(
        input.from,
        Some(Actor::new(input_side.vault_id, pool.token_program_id)),
        "Input vault was not provided"
    );
    let (reserve_in, reserve_out) = (input_side.reserve, output.reserve);

    assert!(
        reserve_in != 0 && reserve_out != 0,
        "Pool reserves must be nonzero"
    );
    let amount_out = amm_core::quote_exact_input(reserve_in, reserve_out, amount_in)
        .expect("reserve * amount_in overflows u128");
    assert!(
        amount_out >= min_amount_out,
        "The live quote is below the minimum output"
    );
    assert!(amount_out != 0, "Swap amounts must be nonzero");

    let reserve_in = reserve_in
        .checked_add(amount_in)
        .expect("the quote already summed the input reserve");
    let reserve_out = reserve_out
        .checked_sub(amount_out)
        .expect("a quote stays below the output reserve");
    let (reserve_a, reserve_b) = if input_side.definition_id == pool.definition_token_a_id {
        (reserve_in, reserve_out)
    } else {
        (reserve_out, reserve_in)
    };

    let payout = withdrawal(
        pool,
        input.receiver.account_id,
        output.vault_id,
        output.definition_id,
        payout,
        amount_out,
    );
    Response::set_state(ActorState::from(&PoolDefinition {
        reserve_a,
        reserve_b,
        ..pool.clone()
    }))
    .send(payout)
}
