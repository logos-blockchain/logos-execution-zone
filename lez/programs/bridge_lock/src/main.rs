use bridge_lock_core::{
    Message, config_account_id, config_bytes, escrow_account_id, holding_account_id, holding_seed,
    read_config,
};
use cross_zone_outbox_core::Message as OutboxMessage;
use lee_core::{
    account::Actor,
    native_token::custody_transfer,
    program::{ReceiveInput, Response, run_actor, write_once},
};
use wrapped_token_core::{MAX_MINT_AMOUNT, Message as WrappedMessage};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
    let program = input.receiver.program_account_id;
    match message {
        Message::Lock {
            outbox,
            amount,
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => {
            assert_top_level(input);

            // Value conservation: the escrow debit is only sound if the message mints what it
            // locks.
            let WrappedMessage::Mint {
                recipient,
                amount: mint_amount,
            } = decode_mint(&payload)
            else {
                panic!("bridge_lock payload must be a wrapped-token mint");
            };
            assert_eq!(
                mint_amount, amount,
                "locked amount must equal the wrapped mint amount"
            );

            // `target_zone` is not checkable here, so a lock aimed at a zone that will not route
            // it still burns.
            let expected_accounts = vec![
                Actor::new(
                    wrapped_token_core::config_account_id(target_account_id),
                    target_account_id,
                ),
                Actor::new(
                    wrapped_token_core::holding_account_id(target_account_id, &recipient),
                    target_account_id,
                ),
            ];
            assert_eq!(
                target_accounts, expected_accounts,
                "target accounts must be the mint's config and the recipient's holding, under the \
                 wrapped token's own shard"
            );
            assert!(
                amount <= MAX_MINT_AMOUNT,
                "locked amount exceeds what the wrapped token will mint"
            );
            // A zero lock would emit a real dispatch and zero-mint into any
            // recipient's wrapped holding.
            assert!(amount > 0, "locked amount must be positive");

            // The holder's signature authorizes its own account only, which is why a lock is
            // received there; the derivation pins the debit target to a genuine bridge-lock
            // holding.
            assert!(input.is_authorized, "holder must authorize the lock");
            let holder = input.receiver.account_id.into_value();

            // The outbox actor's program, not a new message field, carries the proposed route.
            // The config checks it before the debit and the emission are delivered, as the read
            // it replaces did.
            Response::keep()
                .call(
                    Actor::new(config_account_id(program), program),
                    &Message::CheckRoute {
                        outbox_account_id: outbox.program_account_id,
                        target_account_id,
                    },
                )
                .send(custody_transfer(
                    holding_account_id(program, &holder),
                    holding_seed(&holder),
                    escrow_account_id(program),
                    amount,
                ))
                .call(
                    outbox,
                    &OutboxMessage::Emit {
                        target_zone,
                        target_account_id,
                        target_accounts,
                        payload,
                        ordinal,
                    },
                )
        }
        // Nothing releases an escrow, so an emission steered off the pinned route burns the
        // holder's balance with no compensating mint anywhere. This is all that stands between.
        Message::CheckRoute {
            outbox_account_id,
            target_account_id,
        } => {
            assert!(
                input.from_own_program(),
                "the route is only checked for a lock of bridge_lock's own"
            );
            let (outbox, target) = read_config(&input.pre_state)
                .expect("config account holds an outbox and a mint target");
            assert_eq!(
                outbox, outbox_account_id,
                "bridge_lock only emits through the outbox it is pinned to"
            );
            assert_eq!(
                target, target_account_id,
                "bridge_lock only mints through the wrapped token it is pinned to"
            );
            Response::keep()
        }
        // A written shard must already pin exactly these programs rather than being refused,
        // because genesis is replayed onto seeded state during multi-sequencer reconstruction.
        Message::InitConfig {
            outbox_account_id,
            target_account_id,
        } => {
            assert_top_level(input);
            assert_eq!(
                input.receiver.account_id,
                config_account_id(program),
                "the receiver must be the bridge-lock config PDA"
            );
            Response::write(write_once(
                &input.pre_state,
                config_bytes(outbox_account_id, target_account_id).to_vec(),
            ))
        }
    }
}

fn assert_top_level(input: &ReceiveInput) {
    assert!(
        input.origin.is_none(),
        "bridge_lock is only invoked as a top-level user transaction"
    );
}

/// Decodes the cross-zone payload (borsh bytes) into the wrapped-token message it carries.
fn decode_mint(payload: &[u8]) -> WrappedMessage {
    borsh::from_slice(payload).expect("payload decodes to a wrapped-token instruction")
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, ActorState},
        program::{Call, Transition},
    };

    use super::*;

    const BRIDGE_LOCK_ID: AccountId = AccountId::new([4; 32]);
    const OUTBOX_ID: AccountId = AccountId::new([3; 32]);
    const WRAPPED_ID: AccountId = AccountId::new([5; 32]);
    const HOLDER: AccountId = AccountId::new([6; 32]);
    const RECIPIENT: [u8; 32] = [7; 32];
    const ZONE: [u8; 32] = [8; 32];
    const AMOUNT: u128 = 1_000;

    fn config() -> Vec<u8> {
        config_bytes(OUTBOX_ID, WRAPPED_ID).to_vec()
    }

    fn config_actor() -> Actor {
        Actor::new(config_account_id(BRIDGE_LOCK_ID), BRIDGE_LOCK_ID)
    }

    fn holder_actor() -> Actor {
        Actor::new(HOLDER, BRIDGE_LOCK_ID)
    }

    fn outbox_actor() -> Actor {
        Actor::new(
            cross_zone_outbox_core::outbox_pda(OUTBOX_ID, BRIDGE_LOCK_ID, &ZONE, 0),
            OUTBOX_ID,
        )
    }

    fn run(
        receiver: Actor,
        origin: Option<AccountId>,
        is_authorized: bool,
        pre: Vec<u8>,
        message: Message,
    ) -> Transition {
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized,
            pre_state: ActorState::from(pre),
            message: borsh::to_vec(&message).unwrap(),
        };
        receive(&input, message).into_transition(input)
    }

    fn mint_payload(amount: u128) -> Vec<u8> {
        borsh::to_vec(&WrappedMessage::Mint {
            recipient: RECIPIENT,
            amount,
        })
        .expect("the mint serializes")
    }

    fn target_accounts() -> Vec<Actor> {
        vec![
            Actor::new(
                wrapped_token_core::config_account_id(WRAPPED_ID),
                WRAPPED_ID,
            ),
            Actor::new(
                wrapped_token_core::holding_account_id(WRAPPED_ID, &RECIPIENT),
                WRAPPED_ID,
            ),
        ]
    }

    fn lock_message(target_account_id: AccountId, payload: Vec<u8>) -> Message {
        Message::Lock {
            outbox: outbox_actor(),
            amount: AMOUNT,
            target_zone: ZONE,
            target_account_id,
            target_accounts: target_accounts(),
            payload,
            ordinal: 0,
        }
    }

    fn lock(origin: Option<AccountId>, is_authorized: bool, message: Message) -> Transition {
        run(holder_actor(), origin, is_authorized, Vec::new(), message)
    }

    fn check_route(
        outbox_account_id: AccountId,
        target_account_id: AccountId,
        pre: Vec<u8>,
    ) -> Transition {
        run(
            config_actor(),
            Some(holder_actor().program_account_id),
            false,
            pre,
            Message::CheckRoute {
                outbox_account_id,
                target_account_id,
            },
        )
    }

    fn init(origin: Option<AccountId>, target_account_id: AccountId, pre: Vec<u8>) -> Transition {
        run(
            config_actor(),
            origin,
            false,
            pre,
            Message::InitConfig {
                outbox_account_id: OUTBOX_ID,
                target_account_id,
            },
        )
    }

    #[test]
    fn a_lock_pins_its_route_before_it_moves_anything() {
        let transition = lock(None, true, lock_message(WRAPPED_ID, mint_payload(AMOUNT)));

        let holder = HOLDER.into_value();
        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![
                    Call::new(
                        config_actor(),
                        &Message::CheckRoute {
                            outbox_account_id: OUTBOX_ID,
                            target_account_id: WRAPPED_ID,
                        },
                    ),
                    custody_transfer(
                        holding_account_id(BRIDGE_LOCK_ID, &holder),
                        holding_seed(&holder),
                        escrow_account_id(BRIDGE_LOCK_ID),
                        AMOUNT,
                    ),
                    Call::new(
                        outbox_actor(),
                        &OutboxMessage::Emit {
                            target_zone: ZONE,
                            target_account_id: WRAPPED_ID,
                            target_accounts: target_accounts(),
                            payload: mint_payload(AMOUNT),
                            ordinal: 0,
                        },
                    ),
                ],
                Vec::new()
            ),
            "the route is checked first, then the escrow debit, then the emission"
        );
    }

    #[test]
    #[should_panic(expected = "bridge_lock is only invoked as a top-level user transaction")]
    fn a_lock_from_another_program_is_refused() {
        let _transition = lock(
            Some(OUTBOX_ID),
            true,
            lock_message(WRAPPED_ID, mint_payload(AMOUNT)),
        );
    }

    #[test]
    fn the_route_genesis_pinned_is_accepted() {
        assert_eq!(
            check_route(OUTBOX_ID, WRAPPED_ID, config())
                .response
                .post_state,
            None
        );
    }

    #[test]
    #[should_panic(expected = "bridge_lock only emits through the outbox it is pinned to")]
    fn an_outbox_the_config_does_not_pin_is_refused() {
        // The emission is what compensates the escrow debit. Steered to a program of the
        // caller's choosing, the balance is gone and nothing mints on the destination.
        let _transition = check_route(AccountId::new([0xAA; 32]), WRAPPED_ID, config());
    }

    #[test]
    #[should_panic(expected = "bridge_lock only mints through the wrapped token it is pinned to")]
    fn a_mint_target_the_config_does_not_pin_is_refused() {
        let _transition = check_route(OUTBOX_ID, AccountId::new([0xBB; 32]), config());
    }

    #[test]
    #[should_panic(expected = "config account holds an outbox and a mint target")]
    fn an_unwritten_config_authorizes_no_route() {
        let _transition = check_route(OUTBOX_ID, WRAPPED_ID, Vec::new());
    }

    #[test]
    #[should_panic(expected = "the route is only checked for a lock of bridge_lock's own")]
    fn a_route_check_from_outside_bridge_lock_is_refused() {
        let _transition = run(
            config_actor(),
            None,
            false,
            config(),
            Message::CheckRoute {
                outbox_account_id: OUTBOX_ID,
                target_account_id: WRAPPED_ID,
            },
        );
    }

    #[test]
    fn a_first_init_writes_the_route() {
        assert_eq!(
            init(None, WRAPPED_ID, Vec::new()).response.post_state,
            Some(ActorState::from(config()))
        );
    }

    #[test]
    fn replaying_the_same_init_is_a_no_op() {
        assert_eq!(
            init(None, WRAPPED_ID, config()).response.post_state,
            Some(ActorState::from(config()))
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_a_different_route_is_refused() {
        let _transition = init(None, AccountId::new([0xBB; 32]), config());
    }

    #[test]
    #[should_panic(expected = "bridge_lock is only invoked as a top-level user transaction")]
    fn an_init_from_another_program_is_refused() {
        let _transition = init(
            Some(holder_actor().program_account_id),
            WRAPPED_ID,
            Vec::new(),
        );
    }

    #[test]
    #[should_panic(expected = "locked amount must equal the wrapped mint amount")]
    fn a_payload_minting_more_than_is_locked_is_refused() {
        let _transition = lock(
            None,
            true,
            lock_message(WRAPPED_ID, mint_payload(AMOUNT.saturating_mul(2))),
        );
    }

    #[test]
    #[should_panic(expected = "target accounts must be the mint's config and the recipient's")]
    fn target_accounts_are_derived_from_the_proposed_target() {
        // A forged proposed target still has to name that target's own PDAs here, and the config
        // then refuses it.
        let _transition = lock(
            None,
            true,
            lock_message(AccountId::new([0xBB; 32]), mint_payload(AMOUNT)),
        );
    }

    #[test]
    #[should_panic(expected = "holder must authorize the lock")]
    fn a_lock_without_the_holder_is_refused() {
        let _transition = lock(None, false, lock_message(WRAPPED_ID, mint_payload(AMOUNT)));
    }
}
