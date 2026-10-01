#![cfg(test)]
#![expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "fixtures compute overflow boundaries directly"
)]

use amm_core::{
    ExactInput, Message, PoolDefinition, SwapOffer, SwapRequest, compute_liquidity_token_pda,
    compute_liquidity_token_pda_seed, compute_pool_pda, compute_vault_pda, compute_vault_pda_seed,
    swap_transfer,
};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{Action, Call, Origin, ReceiveInput, Transition},
};
use token_core::{
    Delivery, NewTokenDefinition, Notification, TokenDescriptor, TokenKind, expected_sends,
};

const AMM_PROGRAM_ID: AccountId = AccountId::new([1; 32]);
const TOKEN_PROGRAM_ID: AccountId = AccountId::new([15; 32]);
const STRANGER_PROGRAM_ID: AccountId = AccountId::new([0xEE; 32]);
const TOKEN_A_ID: AccountId = AccountId::new([42; 32]);
const TOKEN_B_ID: AccountId = AccountId::new([43; 32]);
const USER_A_ID: AccountId = AccountId::new([45; 32]);
const USER_B_ID: AccountId = AccountId::new([46; 32]);
const USER_LP_ID: AccountId = AccountId::new([47; 32]);
const UNRELATED_ID: AccountId = AccountId::new([4; 32]);

const RESERVE_A: u128 = 1_000;
const RESERVE_B: u128 = 500;
// isqrt(RESERVE_A * RESERVE_B)
const LP_SUPPLY: u128 = 707;

const ADD_MAX_A: u128 = 500;
const ADD_MAX_B: u128 = 200;
const ADD_ACTUAL_A: u128 = 400;
const ADD_ACTUAL_B: u128 = 200;
const ADD_LP: u128 = 282;

const REMOVE_LP: u128 = 100;
const REMOVE_A: u128 = 141;
const REMOVE_B: u128 = 70;

fn pool_id() -> AccountId {
    compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, TOKEN_PROGRAM_ID)
}

fn vault_a_id() -> AccountId {
    compute_vault_pda(AMM_PROGRAM_ID, pool_id(), TOKEN_A_ID)
}

fn vault_b_id() -> AccountId {
    compute_vault_pda(AMM_PROGRAM_ID, pool_id(), TOKEN_B_ID)
}

fn token_lp_id() -> AccountId {
    compute_liquidity_token_pda(AMM_PROGRAM_ID, pool_id())
}

fn pool_base() -> PoolDefinition {
    PoolDefinition {
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        vault_a_id: vault_a_id(),
        vault_b_id: vault_b_id(),
        liquidity_pool_id: token_lp_id(),
        liquidity_pool_supply: LP_SUPPLY,
        reserve_a: RESERVE_A,
        reserve_b: RESERVE_B,
        fees: 0,
        active: true,
    }
}

fn pool_shard(pool: &PoolDefinition) -> ActorState {
    ActorState::from(pool)
}

fn token_actor(account_id: AccountId) -> Actor {
    Actor::new(account_id, TOKEN_PROGRAM_ID)
}

fn definitions(input_is_token_a: bool) -> (AccountId, AccountId) {
    if input_is_token_a {
        (TOKEN_A_ID, TOKEN_B_ID)
    } else {
        (TOKEN_B_ID, TOKEN_A_ID)
    }
}

// Input vault, output vault, input holding, output holding.
fn swap_route(input_is_token_a: bool) -> [AccountId; 4] {
    if input_is_token_a {
        [vault_a_id(), vault_b_id(), USER_A_ID, USER_B_ID]
    } else {
        [vault_b_id(), vault_a_id(), USER_B_ID, USER_A_ID]
    }
}

fn turn(
    pool_account: AccountId,
    pool_state: ActorState,
    origin: Origin,
    message: Vec<u8>,
) -> Transition {
    let input = ReceiveInput {
        receiver: Actor::new(pool_account, AMM_PROGRAM_ID),
        origin,
        is_authorized: false,
        pre_state: pool_state,
        message,
    };
    crate::receive(&input).into_transition(input)
}

fn pool_turn(pool_state: ActorState, origin: Origin, message: Vec<u8>) -> Transition {
    turn(pool_id(), pool_state, origin, message)
}

// A liquidity operation: a user's root delivery to the pool.
fn user_turn(pool_state: ActorState, message: &Message) -> Transition {
    pool_turn(
        pool_state,
        Origin::Root,
        borsh::to_vec(message).expect("the message serializes"),
    )
}

fn written(transition: &Transition) -> PoolDefinition {
    PoolDefinition::try_from(
        transition
            .post_state
            .as_ref()
            .expect("the pool writes its shard"),
    )
    .expect("the pool wrote a pool definition")
}

// Two positions of one guard are the same case only if they are refused for the same reason, so a
// table of positions reads the message rather than settling for any panic.
fn rejection(call: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(call).expect_err("the AMM accepted the proposal");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
        })
        .expect("a panic carries its message")
}

const fn fungible_of(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

fn transfer(
    from: AccountId,
    to: AccountId,
    definition_id: AccountId,
    amount: u128,
    delivery: Delivery,
) -> Call {
    Call::new(
        token_actor(from),
        &token_core::Message::Transfer {
            to,
            descriptor: fungible_of(definition_id),
            amount,
            notify: None,
            delivery,
        },
    )
}

fn withdrawal(
    vault: AccountId,
    to: AccountId,
    definition_id: AccountId,
    amount: u128,
    delivery: Delivery,
) -> Call {
    transfer(vault, to, definition_id, amount, delivery)
        .with_pda_seeds(vec![compute_vault_pda_seed(pool_id(), definition_id)])
}

fn lp_send(message: &token_core::Message) -> Call {
    Call::new(token_actor(token_lp_id()), message)
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool_id())])
}

const fn add_message(
    max_a: u128,
    max_b: u128,
    amount_a: u128,
    amount_b: u128,
    amount_liquidity: u128,
) -> Message {
    Message::AddLiquidity {
        max_amount_to_add_token_a: max_a,
        max_amount_to_add_token_b: max_b,
        amount_to_add_token_a: amount_a,
        amount_to_add_token_b: amount_b,
        amount_liquidity,
        user_a: USER_A_ID,
        user_b: USER_B_ID,
        user_lp: USER_LP_ID,
    }
}

fn add(pool: &PoolDefinition, message: &Message) -> Transition {
    user_turn(pool_shard(pool), message)
}

const fn remove_message(remove_liquidity_amount: u128, amount_a: u128, amount_b: u128) -> Message {
    Message::RemoveLiquidity {
        remove_liquidity_amount,
        amount_to_remove_token_a: amount_a,
        amount_to_remove_token_b: amount_b,
        user_a: USER_A_ID,
        user_b: USER_B_ID,
        user_lp: USER_LP_ID,
    }
}

const fn new_definition_message(token_a_amount: u128, token_b_amount: u128) -> Message {
    Message::NewDefinition {
        token_a_amount,
        token_b_amount,
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        user_a: USER_A_ID,
        user_b: USER_B_ID,
        user_lp: USER_LP_ID,
    }
}

fn offer(definition_id_out: AccountId, amount_out: u128, payout: AccountId) -> SwapOffer {
    SwapOffer {
        definition_id_out,
        amount_out,
        payout,
    }
}

fn request_notification(
    credited_account: AccountId,
    definition_id_in: AccountId,
    amount_in: u128,
    request: SwapRequest,
) -> Vec<u8> {
    borsh::to_vec(&token_core::Message::Notification(Notification {
        credited_account,
        descriptor: fungible_of(definition_id_in),
        amount: amount_in,
        payload: borsh::to_vec(&request).expect("the request serializes"),
    }))
    .expect("the notification serializes")
}

fn notification(
    credited_account: AccountId,
    definition_id_in: AccountId,
    amount_in: u128,
    offer: SwapOffer,
) -> Vec<u8> {
    request_notification(
        credited_account,
        definition_id_in,
        amount_in,
        SwapRequest::Offer(offer),
    )
}

// The input vault's notification to the pool after it credited `amount_in`.
fn swap_turn(
    pool: &PoolDefinition,
    input_is_token_a: bool,
    amount_in: u128,
    amount_out: u128,
) -> Transition {
    let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
    let [input_vault, _, _, user_output] = swap_route(input_is_token_a);
    pool_turn(
        pool_shard(pool),
        Origin::Program(TOKEN_PROGRAM_ID),
        notification(
            input_vault,
            definition_id_in,
            amount_in,
            offer(definition_id_out, amount_out, user_output),
        ),
    )
}

fn swap_on(
    pool: &PoolDefinition,
    input_is_token_a: bool,
    amount_in: u128,
    amount_out: u128,
) -> PoolDefinition {
    written(&swap_turn(pool, input_is_token_a, amount_in, amount_out))
}

fn exact_input_turn(
    pool: &PoolDefinition,
    input_is_token_a: bool,
    amount_in: u128,
    min_amount_out: u128,
    delivery: Delivery,
) -> Transition {
    let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
    let [input_vault, _, _, user_output] = swap_route(input_is_token_a);
    pool_turn(
        pool_shard(pool),
        Origin::Program(TOKEN_PROGRAM_ID),
        request_notification(
            input_vault,
            definition_id_in,
            amount_in,
            SwapRequest::ExactInput(ExactInput {
                definition_id_out,
                min_amount_out,
                payout: user_output,
                delivery,
            }),
        ),
    )
}

#[test]
fn pool_pda_produces_unique_id_for_token_pair() {
    assert_eq!(
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, TOKEN_PROGRAM_ID),
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_B_ID, TOKEN_A_ID, TOKEN_PROGRAM_ID)
    );
}

#[test]
fn the_pool_of_a_stranger_program_is_a_different_address() {
    assert_ne!(
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, TOKEN_PROGRAM_ID),
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, STRANGER_PROGRAM_ID),
        "each token program must get its own pool for a pair"
    );
}

#[test]
fn call_add_liquidity_zero_balance() {
    for (position, max_a, max_b) in [("Token A", 0, ADD_MAX_B), ("Token B", ADD_MAX_A, 0)] {
        assert!(
            rejection(|| {
                let _transition = add(
                    &pool_base(),
                    &add_message(max_a, max_b, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP),
                );
            })
            .contains("Both max-balances must be nonzero"),
            "a zero max balance for {position} was accepted"
        );
    }
}

#[test]
fn call_add_liquidity_actual_amount_zero() {
    for (position, amount_a, amount_b) in
        [("Token A", 0, ADD_ACTUAL_B), ("Token B", ADD_ACTUAL_A, 0)]
    {
        assert!(
            rejection(|| {
                let _transition = add(
                    &pool_base(),
                    &add_message(ADD_MAX_A, ADD_MAX_B, amount_a, amount_b, ADD_LP),
                );
            })
            .contains("A trade amount is 0"),
            "a zero deposit of {position} was accepted"
        );
    }
}

#[should_panic(expected = "Payable LP must be nonzero")]
#[test]
fn call_add_liquidity_payable_lp_zero() {
    let _transition = add(
        &pool_base(),
        &add_message(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, 0),
    );
}

#[should_panic(expected = "Actual trade amounts cannot exceed max_amounts")]
#[test]
fn call_add_liquidity_actual_amount_above_max() {
    let _transition = add(
        &pool_base(),
        &add_message(ADD_MAX_A, ADD_MAX_B, ADD_MAX_A + 1, ADD_ACTUAL_B, ADD_LP),
    );
}

// The pool's live reserves are what tie an add to the price: a caller who proposes the deposit
// that a larger pool would have priced is rejected.
#[should_panic(expected = "Proposed Token A deposit does not match the pool's ideal amount")]
#[test]
fn add_liquidity_inflated_token_a_deposit_is_rejected() {
    let _transition = add(
        &pool_base(),
        &add_message(ADD_MAX_A, ADD_MAX_B, ADD_MAX_A, ADD_ACTUAL_B, ADD_LP),
    );
}

#[should_panic(expected = "Proposed Token B deposit does not match the pool's ideal amount")]
#[test]
fn add_liquidity_inflated_token_b_deposit_is_rejected() {
    let _transition = add(
        &pool_base(),
        &add_message(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B - 1, ADD_LP),
    );
}

#[should_panic(expected = "Proposed LP amount does not match the pool's mint calculation")]
#[test]
fn add_liquidity_inflated_liquidity_mint_is_rejected() {
    let _transition = add(
        &pool_base(),
        &add_message(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP * 2),
    );
}

#[test]
fn call_add_liquidity_reserves_zero() {
    let cases = [
        (
            "Token A",
            PoolDefinition {
                reserve_a: 0,
                ..pool_base()
            },
        ),
        (
            "Token B",
            PoolDefinition {
                reserve_b: 0,
                ..pool_base()
            },
        ),
    ];

    for (position, pool) in cases {
        assert!(
            rejection(|| {
                let _transition = add(
                    &pool,
                    &add_message(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP),
                );
            })
            .contains("Reserves must be nonzero"),
            "an empty {position} reserve was accepted"
        );
    }
}

#[test]
fn call_add_liquidity_successful() {
    let transition = add(
        &pool_base(),
        &add_message(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP),
    );

    assert_eq!(
        written(&transition),
        PoolDefinition {
            liquidity_pool_supply: LP_SUPPLY + ADD_LP,
            reserve_a: RESERVE_A + ADD_ACTUAL_A,
            reserve_b: RESERVE_B + ADD_ACTUAL_B,
            ..pool_base()
        }
    );
    assert_eq!(
        transition.sends,
        vec![
            lp_send(&token_core::Message::Mint {
                to: USER_LP_ID,
                amount: ADD_LP,
            })
            .into(),
            transfer(
                USER_B_ID,
                vault_b_id(),
                TOKEN_B_ID,
                ADD_ACTUAL_B,
                Delivery::Call
            )
            .into(),
            transfer(
                USER_A_ID,
                vault_a_id(),
                TOKEN_A_ID,
                ADD_ACTUAL_A,
                Delivery::Call
            )
            .into(),
        ]
    );
}

#[should_panic(expected = "Remove liquidity amount must be nonzero")]
#[test]
fn call_remove_liquidity_amount_zero() {
    let _transition = user_turn(pool_shard(&pool_base()), &remove_message(0, 0, 0));
}

#[test]
fn call_remove_liquidity_withdraw_amount_zero() {
    for (position, amount_a, amount_b) in [("Token A", 0, REMOVE_B), ("Token B", REMOVE_A, 0)] {
        assert!(
            rejection(|| {
                let _transition = user_turn(
                    pool_shard(&pool_base()),
                    &remove_message(REMOVE_LP, amount_a, amount_b),
                );
            })
            .contains("Withdraw amounts must be nonzero"),
            "a zero withdrawal of {position} was accepted"
        );
    }
}

#[should_panic(expected = "Withdraw amounts must be nonzero")]
#[test]
fn remove_liquidity_worth_nothing_of_one_token_is_refused() {
    // The pool's own price for one LP, so only the nonzero rule keeps the burn from paying out
    // nothing.
    let amount_a = amm_core::withdrawal_share(RESERVE_A, 1, LP_SUPPLY).expect("the share fits");
    let amount_b = amm_core::withdrawal_share(RESERVE_B, 1, LP_SUPPLY).expect("the share fits");
    assert_eq!((amount_a, amount_b), (1, 0));
    let _transition = user_turn(
        pool_shard(&pool_base()),
        &remove_message(1, amount_a, amount_b),
    );
}

#[should_panic(expected = "Pool is inactive")]
#[test]
fn call_remove_liquidity_inactive() {
    let pool = PoolDefinition {
        active: false,
        ..pool_base()
    };
    let _transition = user_turn(
        pool_shard(&pool),
        &remove_message(REMOVE_LP, REMOVE_A, REMOVE_B),
    );
}

#[should_panic(
    expected = "Proposed Token A withdrawal does not match the pool's removal calculation"
)]
#[test]
fn remove_liquidity_inflated_withdrawal_is_rejected() {
    let _transition = user_turn(
        pool_shard(&pool_base()),
        &remove_message(REMOVE_LP, RESERVE_A, REMOVE_B),
    );
}

// 708 LP of a 707 supply would price at 1,001 A / 500 B, so a pool that computed the shares before
// checking the supply would accept these and then underflow the reserves.
#[should_panic(expected = "Removal burns more LP than the pool's supply")]
#[test]
fn remove_liquidity_refuses_burning_more_lp_than_the_supply() {
    let _transition = user_turn(
        pool_shard(&pool_base()),
        &remove_message(LP_SUPPLY + 1, 1_001, 500),
    );
}

#[test]
fn call_remove_liquidity_successful() {
    let transition = user_turn(
        pool_shard(&pool_base()),
        &remove_message(REMOVE_LP, REMOVE_A, REMOVE_B),
    );

    assert_eq!(
        written(&transition),
        PoolDefinition {
            liquidity_pool_supply: LP_SUPPLY - REMOVE_LP,
            reserve_a: RESERVE_A - REMOVE_A,
            reserve_b: RESERVE_B - REMOVE_B,
            ..pool_base()
        }
    );
    assert_eq!(
        transition.sends,
        vec![
            Call::new(
                token_actor(USER_LP_ID),
                &token_core::Message::Burn {
                    descriptor: fungible_of(token_lp_id()),
                    amount: REMOVE_LP,
                    definition: token_lp_id(),
                },
            )
            .into(),
            withdrawal(
                vault_b_id(),
                USER_B_ID,
                TOKEN_B_ID,
                REMOVE_B,
                Delivery::Call
            )
            .into(),
            withdrawal(
                vault_a_id(),
                USER_A_ID,
                TOKEN_A_ID,
                REMOVE_A,
                Delivery::Call
            )
            .into(),
        ]
    );
}

#[test]
fn remove_liquidity_full_drain_deactivates_the_pool() {
    let transition = user_turn(
        pool_shard(&pool_base()),
        &remove_message(LP_SUPPLY, RESERVE_A, RESERVE_B),
    );

    assert_eq!(
        written(&transition),
        PoolDefinition {
            liquidity_pool_supply: 0,
            reserve_a: 0,
            reserve_b: 0,
            active: false,
            ..pool_base()
        }
    );
}

#[should_panic(expected = "Token A should have a nonzero amount")]
#[test]
fn call_new_definition_with_zero_balance_1() {
    let _transition = user_turn(ActorState::empty(), &new_definition_message(0, RESERVE_B));
}

#[should_panic(expected = "Token B should have a nonzero amount")]
#[test]
fn call_new_definition_with_zero_balance_2() {
    let _transition = user_turn(ActorState::empty(), &new_definition_message(RESERVE_A, 0));
}

#[should_panic(expected = "Cannot set up a swap for a token with itself")]
#[test]
fn call_new_definition_same_token_definition() {
    let Message::NewDefinition {
        token_a_amount,
        token_b_amount,
        token_program_id,
        definition_token_a_id,
        user_a,
        user_b,
        user_lp,
        ..
    } = new_definition_message(RESERVE_A, RESERVE_B)
    else {
        unreachable!("the helper builds a new definition");
    };
    let _transition = user_turn(
        ActorState::empty(),
        &Message::NewDefinition {
            token_a_amount,
            token_b_amount,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id: definition_token_a_id,
            user_a,
            user_b,
            user_lp,
        },
    );
}

#[should_panic(expected = "Pool Definition Account ID does not match PDA")]
#[test]
fn call_new_definition_wrong_pool_id() {
    let _transition = turn(
        UNRELATED_ID,
        ActorState::empty(),
        Origin::Root,
        borsh::to_vec(&new_definition_message(RESERVE_A, RESERVE_B))
            .expect("the message serializes"),
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn call_new_definition_cannot_initialize_active_pool() {
    let _transition = user_turn(
        pool_shard(&pool_base()),
        &new_definition_message(RESERVE_A, RESERVE_B),
    );
}

#[test]
fn new_definition_uninitialized_pool_creates_the_liquidity_definition() {
    let transition = user_turn(
        ActorState::empty(),
        &new_definition_message(RESERVE_A, RESERVE_B),
    );

    assert_eq!(written(&transition), pool_base());
    // The supply the pool records and the supply the LP definition is created with are one value.
    assert_eq!(
        transition.sends,
        vec![
            lp_send(&token_core::Message::NewDefinition {
                definition: NewTokenDefinition::Fungible {
                    name: String::from("LP Token"),
                    total_supply: LP_SUPPLY,
                },
                holding: USER_LP_ID,
                metadata: None,
            })
            .into(),
            transfer(
                USER_B_ID,
                vault_b_id(),
                TOKEN_B_ID,
                RESERVE_B,
                Delivery::Call
            )
            .into(),
            transfer(
                USER_A_ID,
                vault_a_id(),
                TOKEN_A_ID,
                RESERVE_A,
                Delivery::Call
            )
            .into(),
        ]
    );
}

#[test]
fn new_definition_lp_asymmetric_amounts() {
    let inactive = PoolDefinition {
        active: false,
        liquidity_pool_supply: 1,
        ..pool_base()
    };
    let transition = user_turn(
        pool_shard(&inactive),
        &new_definition_message(RESERVE_A, RESERVE_B),
    );

    assert_eq!(written(&transition).liquidity_pool_supply, LP_SUPPLY);
    assert_eq!(
        transition.sends.first(),
        Some(
            &lp_send(&token_core::Message::Mint {
                to: USER_LP_ID,
                amount: LP_SUPPLY,
            })
            .into()
        )
    );
}

#[test]
fn new_definition_lp_symmetric_amounts() {
    // token_a = 100, token_b = 100 -> LP = sqrt(10_000) = 100
    let transition = user_turn(ActorState::empty(), &new_definition_message(100, 100));

    assert_eq!(written(&transition).liquidity_pool_supply, 100);
    assert_eq!(
        transition.sends.first(),
        Some(
            &lp_send(&token_core::Message::NewDefinition {
                definition: NewTokenDefinition::Fungible {
                    name: String::from("LP Token"),
                    total_supply: 100,
                },
                holding: USER_LP_ID,
                metadata: None,
            })
            .into()
        )
    );
}

// Reserves are 1,000 A / 500 B, so a leg read against the wrong reserve prices differently. Every
// expected pool below is worked out by hand from `amount_out <= floor(Y * I / (X + I))`: 500 A
// quotes 166 B, 99 A quotes 45 B while 98 A quotes 44 B, and 200 B quotes 285 A. An offer below
// its quote settles too, leaving the surplus in the reserves.
#[test]
fn a_swap_settles_any_offer_the_live_curve_can_afford() {
    let (a_to_b, b_to_a) = (true, false);
    let with_reserves = |reserve_a, reserve_b| PoolDefinition {
        reserve_a,
        reserve_b,
        ..pool_base()
    };
    let settles = |input_is_token_a, amount_in, amount_out, (reserve_a, reserve_b)| {
        assert_eq!(
            swap_on(&pool_base(), input_is_token_a, amount_in, amount_out),
            with_reserves(reserve_a, reserve_b),
            "{amount_in} for {amount_out} (input is token A: {input_is_token_a})"
        );
    };
    let refuses = |pool: PoolDefinition, input_is_token_a, amount_in, amount_out, message: &str| {
        let refusal = rejection(|| {
            let _pool = swap_on(&pool, input_is_token_a, amount_in, amount_out);
        });
        assert!(
            refusal.contains(message),
            "{amount_in} for {amount_out} (input is token A: {input_is_token_a}): {refusal}"
        );
    };

    settles(a_to_b, 500, 166, (1_500, 334));
    settles(a_to_b, 500, 100, (1_500, 400));
    settles(a_to_b, 150, 45, (1_150, 455));
    settles(a_to_b, 99, 45, (1_099, 455));
    settles(b_to_a, 200, 285, (715, 700));
    settles(b_to_a, 200, 250, (750, 700));

    let cannot_afford = "The pool cannot afford this offer at its live price";
    refuses(pool_base(), a_to_b, 500, 167, cannot_afford);
    refuses(pool_base(), a_to_b, 98, 45, cannot_afford);
    refuses(pool_base(), b_to_a, 200, 286, cannot_afford);
    let zero = "Swap amounts must be nonzero";
    refuses(pool_base(), a_to_b, 0, 45, zero);
    refuses(pool_base(), a_to_b, 99, 0, zero);
    refuses(pool_base(), b_to_a, 0, 250, zero);
    let exhausts = "Swap output exhausts the reserve";
    refuses(pool_base(), a_to_b, 1_000_000, 500, exhausts);
    refuses(pool_base(), b_to_a, 1_000_000, 1_000, exhausts);
    let inactive = PoolDefinition {
        active: false,
        ..pool_base()
    };
    refuses(inactive.clone(), a_to_b, 500, 166, "Pool is inactive");
    refuses(inactive, b_to_a, 200, 285, "Pool is inactive");
    let empty = "Pool reserves must be nonzero";
    refuses(with_reserves(0, RESERVE_B), a_to_b, 500, 1, empty);
    refuses(with_reserves(0, RESERVE_B), b_to_a, 200, 1, empty);
    let (huge, overflow) = (u128::MAX / 2 + 1, "overflows u128");
    refuses(with_reserves(RESERVE_A, huge), a_to_b, 2, 1, overflow);
    refuses(with_reserves(huge, RESERVE_B), b_to_a, 2, 1, overflow);
    refuses(with_reserves(u128::MAX, RESERVE_B), a_to_b, 1, 1, overflow);
}

#[test]
fn a_swap_refuses_a_forged_notification() {
    for input_is_token_a in [true, false] {
        let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
        let [input_vault, output_vault, _, user_output] = swap_route(input_is_token_a);
        let honest_offer = offer(definition_id_out, 1, user_output);
        let honest = notification(input_vault, definition_id_in, 100, honest_offer);
        let forgeries = [
            // Not from the pool's token program, so it is not a swap at all.
            (
                "token program",
                Origin::Program(STRANGER_PROGRAM_ID),
                honest,
                "an AMM message must decode",
            ),
            (
                "credited account",
                Origin::Program(TOKEN_PROGRAM_ID),
                notification(UNRELATED_ID, definition_id_in, 100, honest_offer),
                "Input vault was not provided",
            ),
            (
                "input definition",
                Origin::Program(TOKEN_PROGRAM_ID),
                notification(input_vault, token_lp_id(), 100, honest_offer),
                "AccountId is not a token type for the pool",
            ),
            (
                "output definition",
                Origin::Program(TOKEN_PROGRAM_ID),
                notification(
                    input_vault,
                    definition_id_in,
                    100,
                    offer(definition_id_in, 1, user_output),
                ),
                "AccountId is not a token type for the pool",
            ),
            // A real vault of the pool, credited with the other side's token.
            (
                "vault order",
                Origin::Program(TOKEN_PROGRAM_ID),
                notification(output_vault, definition_id_in, 100, honest_offer),
                "Input vault was not provided",
            ),
        ];
        for (field, origin, message, expected) in forgeries {
            assert!(
                rejection(|| {
                    let _transition = pool_turn(pool_shard(&pool_base()), origin, message);
                })
                .contains(expected),
                "a forged {field} was accepted (input is token A: {input_is_token_a})"
            );
        }
    }
}

// The offer, not the quote, is what moves: the surplus these offers leave stays in the pool.
#[test]
fn a_swap_pays_the_signed_amounts_and_seeds_only_the_withdrawal() {
    for (input_is_token_a, amount_in, amount_out) in [(true, 500, 100), (false, 200, 250)] {
        let (_, definition_id_out) = definitions(input_is_token_a);
        let [_, output_vault, _, user_output] = swap_route(input_is_token_a);

        assert_eq!(
            swap_turn(&pool_base(), input_is_token_a, amount_in, amount_out).sends,
            vec![
                withdrawal(
                    output_vault,
                    user_output,
                    definition_id_out,
                    amount_out,
                    Delivery::Call
                )
                .into()
            ]
        );
    }
}

// A wallet's swap is one token transfer; the token program's own sends carry it to the pool and
// predict the payout a private trader assumes.
#[test]
fn a_swap_is_a_notified_transfer_whose_payout_the_token_program_predicts() {
    let (definition_id_in, definition_id_out) = definitions(true);
    let [input_vault, output_vault, user_input, user_output] = swap_route(true);
    let pool = Actor::new(pool_id(), AMM_PROGRAM_ID);
    let trade = swap_transfer(
        pool,
        input_vault,
        fungible_of(definition_id_in),
        99,
        SwapRequest::Offer(offer(definition_id_out, 45, user_output)),
    );

    let inline = |action: Action| {
        let Action::Call(Call { to, message, .. }) = action else {
            panic!("a token send is an inline call");
        };
        (to, message)
    };
    let decoded = |message: &[u8]| -> token_core::Message {
        borsh::from_slice(message).expect("a token send carries a token message")
    };
    let [credit] = <[Action; 1]>::try_from(expected_sends(token_actor(user_input), &trade))
        .expect("a transfer sends one credit");
    let (credit_to, credit_message) = inline(credit);
    assert_eq!(credit_to, token_actor(input_vault));
    let [notice] = <[Action; 1]>::try_from(expected_sends(
        token_actor(input_vault),
        &decoded(&credit_message),
    ))
    .expect("a notified credit sends one notification");
    let (notice_to, notice_message) = inline(notice);
    assert_eq!(notice_to, pool);

    let settled = pool_turn(
        pool_shard(&pool_base()),
        Origin::Program(TOKEN_PROGRAM_ID),
        notice_message,
    );
    let [payout] = <[Action; 1]>::try_from(settled.sends).expect("a swap sends one withdrawal");
    let (payout_to, payout_message) = inline(payout);
    assert_eq!(payout_to, token_actor(output_vault));
    assert_eq!(
        expected_sends(token_actor(output_vault), &decoded(&payout_message)),
        vec![
            Call::new(
                token_actor(user_output),
                &token_core::Message::Credit {
                    descriptor: fungible_of(definition_id_out),
                    amount: 45,
                    notify: None,
                },
            )
            .into()
        ]
    );
}

#[test]
fn a_swap_refuses_a_trader_holding_that_is_a_vault() {
    for input_is_token_a in [true, false] {
        let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
        let [input_vault, output_vault, ..] = swap_route(input_is_token_a);
        for vault in [input_vault, output_vault] {
            assert!(
                rejection(|| {
                    let _transition = pool_turn(
                        pool_shard(&pool_base()),
                        Origin::Program(TOKEN_PROGRAM_ID),
                        notification(
                            input_vault,
                            definition_id_in,
                            99,
                            offer(definition_id_out, 45, vault),
                        ),
                    );
                })
                .contains("A trader holding cannot be a pool vault"),
                "the payout was accepted as the vault {vault}"
            );
        }
    }
}

#[test]
fn an_exact_input_swap_pays_its_live_quote_by_cast() {
    for (input_is_token_a, amount_in, min_amount_out, quote, (reserve_a, reserve_b)) in [
        (true, 500, 166, 166, (1_500, 334)),
        (false, 200, 100, 285, (715, 700)),
    ] {
        let (_, definition_id_out) = definitions(input_is_token_a);
        let [_, output_vault, _, user_output] = swap_route(input_is_token_a);

        let transition = exact_input_turn(
            &pool_base(),
            input_is_token_a,
            amount_in,
            min_amount_out,
            Delivery::Cast,
        );

        assert_eq!(
            written(&transition),
            PoolDefinition {
                reserve_a,
                reserve_b,
                ..pool_base()
            }
        );
        assert_eq!(
            transition.sends,
            vec![
                withdrawal(
                    output_vault,
                    user_output,
                    definition_id_out,
                    quote,
                    Delivery::Cast
                )
                .into()
            ]
        );
    }
}

#[test]
fn an_exact_input_swap_pays_its_live_quote_by_call_when_asked() {
    assert_eq!(
        exact_input_turn(&pool_base(), true, 500, 166, Delivery::Call).sends,
        vec![withdrawal(vault_b_id(), USER_B_ID, TOKEN_B_ID, 166, Delivery::Call).into()]
    );
}

#[should_panic(expected = "The live quote is below the minimum output")]
#[test]
fn an_exact_input_swap_refuses_a_minimum_above_its_live_quote() {
    let _transition = exact_input_turn(&pool_base(), true, 500, 167, Delivery::Cast);
}

#[should_panic(expected = "Swap amounts must be nonzero")]
#[test]
fn an_exact_input_swap_refuses_an_input_that_quotes_nothing() {
    let _transition = exact_input_turn(&pool_base(), true, 1, 0, Delivery::Cast);
}
