#![cfg(test)]
#![expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "fixtures compute overflow boundaries directly"
)]

use amm_core::{
    Message, PoolDefinition, SwapRequest, compute_liquidity_token_pda,
    compute_liquidity_token_pda_seed, compute_pool_pda, compute_vault_pda, compute_vault_pda_seed,
    swap_transfer,
};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{Call, Cast, ReceiveInput, Transition},
};
use token_core::{NewTokenDefinition, Notification, TokenDescriptor, TokenHolding, TokenKind};

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

fn pool_actor_state(pool: &PoolDefinition) -> ActorState {
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

fn transition_at(
    pool_account: AccountId,
    pool_state: ActorState,
    from: Option<Actor>,
    message: Vec<u8>,
) -> Transition {
    let input = ReceiveInput {
        receiver: Actor::new(pool_account, AMM_PROGRAM_ID),
        from,
        is_authorized: false,
        pre_state: pool_state,
        message,
    };
    crate::handle_message(&input).into_transition(input)
}

fn pool_transition(pool_state: ActorState, from: Option<Actor>, message: Vec<u8>) -> Transition {
    transition_at(pool_id(), pool_state, from, message)
}

// A liquidity operation: a user's root delivery to the pool.
fn user_transition(pool_state: ActorState, message: &Message) -> Transition {
    pool_transition(
        pool_state,
        None,
        borsh::to_vec(message).expect("the message serializes"),
    )
}

fn written(transition: &Transition) -> PoolDefinition {
    PoolDefinition::try_from(
        transition
            .response
            .post_state
            .as_ref()
            .expect("the pool writes its actor state"),
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

fn transfer(from: AccountId, to: AccountId, definition_id: AccountId, amount: u128) -> Call {
    Call::new(
        token_actor(from),
        &token_core::Message::Transfer {
            to,
            descriptor: fungible_of(definition_id),
            amount,
            notify: None,
        },
    )
}

fn withdrawal(vault: AccountId, to: AccountId, definition_id: AccountId, amount: u128) -> Call {
    transfer(vault, to, definition_id, amount)
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
    user_transition(pool_actor_state(pool), message)
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

fn request(definition_id_out: AccountId, min_amount_out: u128, payout: AccountId) -> SwapRequest {
    SwapRequest {
        definition_id_out,
        min_amount_out,
        payout,
    }
}

fn notification(definition_id_in: AccountId, amount_in: u128, request: SwapRequest) -> Vec<u8> {
    borsh::to_vec(&token_core::Message::Notification(Notification {
        descriptor: fungible_of(definition_id_in),
        amount: amount_in,
        payload: borsh::to_vec(&request).expect("the request serializes"),
    }))
    .expect("the notification serializes")
}

// The input vault's notification to the pool after it credited `amount_in`.
fn swap_transition(
    pool: &PoolDefinition,
    input_is_token_a: bool,
    amount_in: u128,
    min_amount_out: u128,
) -> Transition {
    let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
    let [input_vault, _, _, user_output] = swap_route(input_is_token_a);
    pool_transition(
        pool_actor_state(pool),
        Some(token_actor(input_vault)),
        notification(
            definition_id_in,
            amount_in,
            request(definition_id_out, min_amount_out, user_output),
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
        (transition.response.calls, transition.response.casts),
        (
            vec![
                lp_send(&token_core::Message::Mint {
                    to: USER_LP_ID,
                    amount: ADD_LP,
                }),
                transfer(USER_B_ID, vault_b_id(), TOKEN_B_ID, ADD_ACTUAL_B),
                transfer(USER_A_ID, vault_a_id(), TOKEN_A_ID, ADD_ACTUAL_A),
            ],
            Vec::new()
        )
    );
}

#[should_panic(expected = "Remove liquidity amount must be nonzero")]
#[test]
fn call_remove_liquidity_amount_zero() {
    let _transition = user_transition(pool_actor_state(&pool_base()), &remove_message(0, 0, 0));
}

#[test]
fn call_remove_liquidity_withdraw_amount_zero() {
    for (position, amount_a, amount_b) in [("Token A", 0, REMOVE_B), ("Token B", REMOVE_A, 0)] {
        assert!(
            rejection(|| {
                let _transition = user_transition(
                    pool_actor_state(&pool_base()),
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
    let _transition = user_transition(
        pool_actor_state(&pool_base()),
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
    let _transition = user_transition(
        pool_actor_state(&pool),
        &remove_message(REMOVE_LP, REMOVE_A, REMOVE_B),
    );
}

#[should_panic(
    expected = "Proposed Token A withdrawal does not match the pool's removal calculation"
)]
#[test]
fn remove_liquidity_inflated_withdrawal_is_rejected() {
    let _transition = user_transition(
        pool_actor_state(&pool_base()),
        &remove_message(REMOVE_LP, RESERVE_A, REMOVE_B),
    );
}

// 708 LP of a 707 supply would price at 1,001 A / 500 B, so a pool that computed the shares before
// checking the supply would accept these and then underflow the reserves.
#[should_panic(expected = "Removal burns more LP than the pool's supply")]
#[test]
fn remove_liquidity_refuses_burning_more_lp_than_the_supply() {
    let _transition = user_transition(
        pool_actor_state(&pool_base()),
        &remove_message(LP_SUPPLY + 1, 1_001, 500),
    );
}

#[test]
fn call_remove_liquidity_successful() {
    let transition = user_transition(
        pool_actor_state(&pool_base()),
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
        (transition.response.calls, transition.response.casts),
        (
            vec![
                Call::new(
                    token_actor(USER_LP_ID),
                    &token_core::Message::Burn {
                        descriptor: fungible_of(token_lp_id()),
                        amount: REMOVE_LP,
                        definition: token_lp_id(),
                    },
                ),
                withdrawal(vault_b_id(), USER_B_ID, TOKEN_B_ID, REMOVE_B),
                withdrawal(vault_a_id(), USER_A_ID, TOKEN_A_ID, REMOVE_A),
            ],
            Vec::new()
        )
    );
}

#[test]
fn remove_liquidity_full_drain_deactivates_the_pool() {
    let transition = user_transition(
        pool_actor_state(&pool_base()),
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
    let _transition = user_transition(ActorState::empty(), &new_definition_message(0, RESERVE_B));
}

#[should_panic(expected = "Token B should have a nonzero amount")]
#[test]
fn call_new_definition_with_zero_balance_2() {
    let _transition = user_transition(ActorState::empty(), &new_definition_message(RESERVE_A, 0));
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
    let _transition = user_transition(
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
    let _transition = transition_at(
        UNRELATED_ID,
        ActorState::empty(),
        None,
        borsh::to_vec(&new_definition_message(RESERVE_A, RESERVE_B))
            .expect("the message serializes"),
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn call_new_definition_cannot_initialize_active_pool() {
    let _transition = user_transition(
        pool_actor_state(&pool_base()),
        &new_definition_message(RESERVE_A, RESERVE_B),
    );
}

#[test]
fn new_definition_uninitialized_pool_creates_the_liquidity_definition() {
    let transition = user_transition(
        ActorState::empty(),
        &new_definition_message(RESERVE_A, RESERVE_B),
    );

    assert_eq!(written(&transition), pool_base());
    // The supply the pool records and the supply the LP definition is created with are one value.
    assert_eq!(
        (transition.response.calls, transition.response.casts),
        (
            vec![
                lp_send(&token_core::Message::NewDefinition {
                    definition: NewTokenDefinition::Fungible {
                        name: String::from("LP Token"),
                        total_supply: LP_SUPPLY,
                    },
                    holding: USER_LP_ID,
                    metadata: None,
                }),
                transfer(USER_B_ID, vault_b_id(), TOKEN_B_ID, RESERVE_B),
                transfer(USER_A_ID, vault_a_id(), TOKEN_A_ID, RESERVE_A),
            ],
            Vec::new()
        )
    );
}

#[test]
fn new_definition_lp_asymmetric_amounts() {
    let inactive = PoolDefinition {
        active: false,
        liquidity_pool_supply: 1,
        ..pool_base()
    };
    let transition = user_transition(
        pool_actor_state(&inactive),
        &new_definition_message(RESERVE_A, RESERVE_B),
    );

    assert_eq!(written(&transition).liquidity_pool_supply, LP_SUPPLY);
    assert_eq!(
        transition.response.calls.first(),
        Some(&lp_send(&token_core::Message::Mint {
            to: USER_LP_ID,
            amount: LP_SUPPLY,
        }))
    );
}

#[test]
fn new_definition_lp_symmetric_amounts() {
    // token_a = 100, token_b = 100 -> LP = sqrt(10_000) = 100
    let transition = user_transition(ActorState::empty(), &new_definition_message(100, 100));

    assert_eq!(written(&transition).liquidity_pool_supply, 100);
    assert_eq!(
        transition.response.calls.first(),
        Some(&lp_send(&token_core::Message::NewDefinition {
            definition: NewTokenDefinition::Fungible {
                name: String::from("LP Token"),
                total_supply: 100,
            },
            holding: USER_LP_ID,
            metadata: None,
        }))
    );
}

#[test]
fn a_swap_refuses_a_zero_input_an_unusable_pool_or_an_overflowing_quote() {
    let (a_to_b, b_to_a) = (true, false);
    let with_reserves = |reserve_a, reserve_b| PoolDefinition {
        reserve_a,
        reserve_b,
        ..pool_base()
    };
    let refuses = |pool: PoolDefinition, input_is_token_a, amount_in, message: &str| {
        let refusal = rejection(|| {
            let _transition = swap_transition(&pool, input_is_token_a, amount_in, 0);
        });
        assert!(
            refusal.contains(message),
            "{amount_in} in (input is token A: {input_is_token_a}): {refusal}"
        );
    };

    let zero = "Swap amounts must be nonzero";
    refuses(pool_base(), a_to_b, 0, zero);
    refuses(pool_base(), b_to_a, 0, zero);
    let inactive = PoolDefinition {
        active: false,
        ..pool_base()
    };
    refuses(inactive.clone(), a_to_b, 500, "Pool is inactive");
    refuses(inactive, b_to_a, 200, "Pool is inactive");
    let empty = "Pool reserves must be nonzero";
    refuses(with_reserves(0, RESERVE_B), a_to_b, 500, empty);
    refuses(with_reserves(0, RESERVE_B), b_to_a, 200, empty);
    let (huge, overflow) = (u128::MAX / 2 + 1, "overflows u128");
    refuses(with_reserves(RESERVE_A, huge), a_to_b, 2, overflow);
    refuses(with_reserves(huge, RESERVE_B), b_to_a, 2, overflow);
    refuses(with_reserves(u128::MAX, RESERVE_B), a_to_b, 1, overflow);
}

#[test]
fn a_swap_refuses_a_forged_notification() {
    for input_is_token_a in [true, false] {
        let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
        let [input_vault, output_vault, _, user_output] = swap_route(input_is_token_a);
        let honest_request = request(definition_id_out, 1, user_output);
        let honest = notification(definition_id_in, 100, honest_request);
        let forgeries = [
            // Not from the pool's token program, so it is not a swap at all.
            (
                "token program",
                Actor::new(input_vault, STRANGER_PROGRAM_ID),
                honest.clone(),
                "an AMM message must decode",
            ),
            (
                "credited account",
                token_actor(UNRELATED_ID),
                honest,
                "Input vault was not provided",
            ),
            (
                "input definition",
                token_actor(input_vault),
                notification(token_lp_id(), 100, honest_request),
                "AccountId is not a token type for the pool",
            ),
            (
                "output definition",
                token_actor(input_vault),
                notification(
                    definition_id_in,
                    100,
                    request(definition_id_in, 1, user_output),
                ),
                "AccountId is not a token type for the pool",
            ),
            // A real vault of the pool, credited with the other side's token.
            (
                "vault order",
                token_actor(output_vault),
                notification(definition_id_in, 100, honest_request),
                "Input vault was not provided",
            ),
        ];
        for (field, from, message, expected) in forgeries {
            assert!(
                rejection(|| {
                    let _transition =
                        pool_transition(pool_actor_state(&pool_base()), Some(from), message);
                })
                .contains(expected),
                "a forged {field} was accepted (input is token A: {input_is_token_a})"
            );
        }
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
        request(definition_id_out, 45, user_output),
    );

    let inline = |call: Call| (call.to, call.message);
    let decoded = |message: &[u8]| -> token_core::Message {
        borsh::from_slice(message).expect("a token send carries a token message")
    };
    let holding = |definition_id, balance| {
        ActorState::from(&TokenHolding::Fungible {
            definition_id,
            balance,
        })
    };
    let sends = |account_id, from, pre_state, message: &token_core::Message| {
        let input = ReceiveInput {
            receiver: token_actor(account_id),
            from,
            is_authorized: true,
            pre_state,
            message: borsh::to_vec(message).expect("the message serializes"),
        };
        let response = token_program::handle_message(&input, message.clone());
        (response.calls, response.casts)
    };
    let (credit_calls, credits) = sends(user_input, None, holding(definition_id_in, 99), &trade);
    assert!(credit_calls.is_empty(), "a transfer casts its credit");
    let [credit] = <[Cast; 1]>::try_from(credits).expect("a transfer casts one credit");
    assert_eq!(credit.to, token_actor(input_vault));
    let (notices, notice_casts) = sends(
        input_vault,
        Some(token_actor(user_input)),
        holding(definition_id_in, RESERVE_A),
        &decoded(&credit.message),
    );
    assert!(notice_casts.is_empty(), "a credit calls its notification");
    let [notice] =
        <[Call; 1]>::try_from(notices).expect("a notified credit sends one notification");
    let (notice_to, notice_message) = inline(notice);
    assert_eq!(notice_to, pool);

    let settled = pool_transition(
        pool_actor_state(&pool_base()),
        Some(token_actor(input_vault)),
        notice_message,
    );
    assert!(
        settled.response.casts.is_empty(),
        "a pool calls its withdrawal"
    );
    let [payout] =
        <[Call; 1]>::try_from(settled.response.calls).expect("a swap sends one withdrawal");
    let (payout_to, payout_message) = inline(payout);
    assert_eq!(payout_to, token_actor(output_vault));
    assert_eq!(
        sends(
            output_vault,
            Some(pool),
            holding(definition_id_out, RESERVE_B),
            &decoded(&payout_message),
        ),
        (
            Vec::new(),
            vec![Cast::new(
                token_actor(user_output),
                &token_core::Message::Credit {
                    descriptor: fungible_of(definition_id_out),
                    amount: 45,
                    notify: None,
                },
            )]
        )
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
                    let _transition = pool_transition(
                        pool_actor_state(&pool_base()),
                        Some(token_actor(input_vault)),
                        notification(definition_id_in, 99, request(definition_id_out, 45, vault)),
                    );
                })
                .contains("A trader holding cannot be a pool vault"),
                "the payout was accepted as the vault {vault}"
            );
        }
    }
}

// Reserves are 1,000 A / 500 B, so a leg read against the wrong reserve prices differently: 500 A
// quotes floor(500 * 500 / 1,500) = 166 B and 200 B quotes floor(1,000 * 200 / 700) = 285 A.
#[test]
fn a_swap_pays_its_live_quote() {
    for (input_is_token_a, amount_in, min_amount_out, quote, (reserve_a, reserve_b)) in [
        (true, 500, 166, 166, (1_500, 334)),
        (false, 200, 100, 285, (715, 700)),
    ] {
        let (_, definition_id_out) = definitions(input_is_token_a);
        let [_, output_vault, _, user_output] = swap_route(input_is_token_a);

        let transition = swap_transition(&pool_base(), input_is_token_a, amount_in, min_amount_out);

        assert_eq!(
            written(&transition),
            PoolDefinition {
                reserve_a,
                reserve_b,
                ..pool_base()
            }
        );
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![withdrawal(
                    output_vault,
                    user_output,
                    definition_id_out,
                    quote
                )],
                Vec::new()
            )
        );
    }
}

#[should_panic(expected = "The live quote is below the minimum output")]
#[test]
fn a_swap_refuses_a_minimum_above_its_live_quote() {
    let _transition = swap_transition(&pool_base(), true, 500, 167);
}

#[should_panic(expected = "Swap amounts must be nonzero")]
#[test]
fn a_swap_refuses_an_input_that_quotes_nothing() {
    let _transition = swap_transition(&pool_base(), true, 1, 0);
}
