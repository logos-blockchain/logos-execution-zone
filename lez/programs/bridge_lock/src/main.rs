use bridge_lock_core::{
    Message, config_account_id, config_bytes, escrow_account_id, holding_account_id, holding_seed,
    read_config,
};
use cross_zone_outbox_core::Message as OutboxMessage;
use lee_core::{
    account::Actor,
    native_token::custody_transfer,
    program::{ReceiveInput, Response, write_once},
};
use wrapped_token_core::{MAX_MINT_AMOUNT, Message as WrappedMessage};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let program = input.receiver.program_account_id;
    match message {
        Message::Lock {
            outbox,
            amount,
            emission,
        } => {
            assert_top_level(input);

            // Value conservation: the escrow debit is only sound if the message mints what it
            // locks.
            let WrappedMessage::Mint {
                recipient,
                amount: mint_amount,
            } = decode_mint(&emission.payload)
            else {
                panic!("bridge_lock payload must be a wrapped-token mint");
            };
            assert_eq!(
                mint_amount, amount,
                "locked amount must equal the wrapped mint amount"
            );

            let target_account_id = emission.target_account_id;
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
                emission.target_accounts, expected_accounts,
                "target accounts must be the mint's config and the recipient's holding, under the \
                 wrapped token's own actor state"
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
            Response::keep_state()
                .send_sync(
                    Actor::new(config_account_id(program), program),
                    &Message::CheckRoute {
                        outbox_account_id: outbox.program_account_id,
                        target_account_id,
                        target_zone: emission.target_zone,
                    },
                )
                .send(custody_transfer(
                    holding_account_id(program, &holder),
                    holding_seed(&holder),
                    escrow_account_id(program),
                    amount,
                ))
                .send_sync(
                    outbox,
                    &OutboxMessage::Emit {
                        target_zone: emission.target_zone,
                        target_account_id,
                        target_accounts: emission.target_accounts,
                        payload: emission.payload,
                        ordinal: emission.ordinal,
                    },
                )
        }
        // Nothing releases an escrow and the wrapped token has no burn, so a lock off the pinned
        // route (another outbox, another mint target, or a zone nothing carries it to) debits the
        // holder for ever with no compensating mint anywhere.
        Message::CheckRoute {
            outbox_account_id,
            target_account_id,
            target_zone,
        } => {
            assert!(
                input.from_own_program(),
                "the route is only checked for a lock of bridge_lock's own"
            );
            let (outbox, target, lock_target_zones) = read_config(&input.pre_state)
                .expect("config account holds an outbox, a mint target and the zones it locks to");
            assert_eq!(
                outbox, outbox_account_id,
                "bridge_lock only emits through the outbox it is pinned to"
            );
            assert_eq!(
                target, target_account_id,
                "bridge_lock only mints through the wrapped token it is pinned to"
            );
            assert!(
                lock_target_zones.contains(&target_zone),
                "bridge_lock only locks to a zone it is pinned to"
            );
            Response::keep_state()
        }
        // A written actor state must already pin exactly these programs rather than being refused,
        // because genesis is replayed onto seeded state during multi-sequencer reconstruction.
        Message::InitConfig {
            outbox_account_id,
            target_account_id,
            lock_target_zones,
        } => {
            assert_top_level(input);
            assert_eq!(
                input.receiver.account_id,
                config_account_id(program),
                "the receiver must be the bridge-lock config PDA"
            );
            Response::set_state(write_once(
                &input.pre_state,
                config_bytes(outbox_account_id, target_account_id, &lock_target_zones),
            ))
        }
    }
}

fn assert_top_level(input: &ReceiveInput) {
    assert!(
        input.from.is_none(),
        "bridge_lock is only invoked as a top-level user transaction"
    );
}

/// Decodes the cross-zone payload (borsh bytes) into the wrapped-token message it carries.
fn decode_mint(payload: &[u8]) -> WrappedMessage {
    borsh::from_slice(payload).expect("payload decodes to a wrapped-token instruction")
}

#[cfg(test)]
mod tests {
    use bridge_lock_core::CrossZoneEmission;
    use lee_core::{
        account::{AccountId, ActorState},
        program::{SyncMessage, Transition},
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
        config_bytes(OUTBOX_ID, WRAPPED_ID, &[ZONE])
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
            from: origin.map(|sender| Actor::new(sender, sender)),
            is_authorized,
            pre_state: ActorState::from(pre),
            message: borsh::to_vec(&message).unwrap(),
        };
        handle_message(&input, message).into_transition(input)
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
            emission: CrossZoneEmission {
                target_zone: ZONE,
                target_account_id,
                target_accounts: target_accounts(),
                payload,
                ordinal: 0,
            },
        }
    }

    fn lock(origin: Option<AccountId>, is_authorized: bool, message: Message) -> Transition {
        run(holder_actor(), origin, is_authorized, Vec::new(), message)
    }

    fn check_route(
        outbox_account_id: AccountId,
        target_account_id: AccountId,
        target_zone: [u8; 32],
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
                target_zone,
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
                lock_target_zones: vec![ZONE],
            },
        )
    }

    #[test]
    fn a_lock_pins_its_route_before_it_moves_anything() {
        let transition = lock(None, true, lock_message(WRAPPED_ID, mint_payload(AMOUNT)));

        let holder = HOLDER.into_value();
        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
            (
                vec![
                    SyncMessage::new(
                        config_actor(),
                        &Message::CheckRoute {
                            outbox_account_id: OUTBOX_ID,
                            target_account_id: WRAPPED_ID,
                            target_zone: ZONE,
                        },
                    ),
                    custody_transfer(
                        holding_account_id(BRIDGE_LOCK_ID, &holder),
                        holding_seed(&holder),
                        escrow_account_id(BRIDGE_LOCK_ID),
                        AMOUNT
                    ),
                    SyncMessage::new(
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
            check_route(OUTBOX_ID, WRAPPED_ID, ZONE, config())
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
        let _transition = check_route(AccountId::new([0xAA; 32]), WRAPPED_ID, ZONE, config());
    }

    #[test]
    #[should_panic(expected = "bridge_lock only mints through the wrapped token it is pinned to")]
    fn a_mint_target_the_config_does_not_pin_is_refused() {
        let _transition = check_route(OUTBOX_ID, AccountId::new([0xBB; 32]), ZONE, config());
    }

    #[test]
    #[should_panic(expected = "bridge_lock only locks to a zone it is pinned to")]
    fn a_lock_to_a_zone_the_config_does_not_pin_is_refused() {
        let _transition = check_route(OUTBOX_ID, WRAPPED_ID, [0xCC; 32], config());
    }

    #[test]
    fn a_lock_to_any_pinned_zone_is_accepted() {
        let two_zones = config_bytes(OUTBOX_ID, WRAPPED_ID, &[[0xCC; 32], ZONE]);
        assert_eq!(
            check_route(OUTBOX_ID, WRAPPED_ID, ZONE, two_zones)
                .response
                .post_state,
            None
        );
    }

    #[test]
    #[should_panic(expected = "bridge_lock only locks to a zone it is pinned to")]
    fn a_config_pinning_no_zone_locks_nowhere() {
        let _transition = check_route(
            OUTBOX_ID,
            WRAPPED_ID,
            ZONE,
            config_bytes(OUTBOX_ID, WRAPPED_ID, &[]),
        );
    }

    #[test]
    #[should_panic(expected = "config account holds an outbox, a mint target and the zones")]
    fn an_unwritten_config_authorizes_no_route() {
        let _transition = check_route(OUTBOX_ID, WRAPPED_ID, ZONE, Vec::new());
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
                target_zone: ZONE,
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
    #[should_panic(expected = "actor state already holds different data")]
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
