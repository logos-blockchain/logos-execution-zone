use amm_core::{PoolDefinition, SwapRequest};
use lee_core::{
    account::ActorState,
    program::{ReceiveInput, Response},
};
use token_core::{Delivery, Notification};

use crate::sends::withdrawal;

// Accepts any offer the live curve can afford and keeps the rest of the quote in the reserves.
// Vault backing, not a guard here, keeps the paid-out reserve real: only this program can debit
// a vault, and every reserve change it records is paired with an equal transfer.
pub fn swap(input: &ReceiveInput, pool: &PoolDefinition, notification: &Notification) -> Response {
    let request: SwapRequest =
        borsh::from_slice(&notification.payload).expect("a swap notification must carry an offer");
    let (definition_id_out, offered_out, payout, delivery) = match request {
        SwapRequest::Offer(offer) => (
            offer.definition_id_out,
            Some(offer.amount_out),
            offer.payout,
            Delivery::Call,
        ),
        SwapRequest::ExactInput(exact) => {
            (exact.definition_id_out, None, exact.payout, exact.delivery)
        }
    };
    let amount_in = notification.amount;

    assert!(
        amount_in != 0 && offered_out != Some(0),
        "Swap amounts must be nonzero"
    );
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
        notification.credited_account, input_side.vault_id,
        "Input vault was not provided"
    );
    let (reserve_in, reserve_out) = (input_side.reserve, output.reserve);

    assert!(
        reserve_in != 0 && reserve_out != 0,
        "Pool reserves must be nonzero"
    );
    let live_quote = || {
        amm_core::quote_exact_input(reserve_in, reserve_out, amount_in)
            .expect("reserve * amount_in overflows u128")
    };
    let amount_out = match request {
        SwapRequest::Offer(offer) => {
            assert!(
                offer.amount_out < reserve_out,
                "Swap output exhausts the reserve"
            );
            assert!(
                offer.amount_out <= live_quote(),
                "The pool cannot afford this offer at its live price"
            );
            offer.amount_out
        }
        SwapRequest::ExactInput(exact) => {
            let quote = live_quote();
            assert!(
                quote >= exact.min_amount_out,
                "The live quote is below the minimum output"
            );
            assert!(quote != 0, "Swap amounts must be nonzero");
            assert!(quote < reserve_out, "Swap output exhausts the reserve");
            quote
        }
    };

    let reserve_in = reserve_in
        .checked_add(amount_in)
        .expect("the quote already summed the input reserve");
    let reserve_out = reserve_out
        .checked_sub(amount_out)
        .expect("checked against the reserve above");
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
        delivery,
    );
    Response::write(ActorState::from(&PoolDefinition {
        reserve_a,
        reserve_b,
        ..pool.clone()
    }))
    .send(payout)
}
