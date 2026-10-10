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

lee_core::define_actor_logic!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
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
            Response::keep_state()
        }
        // A written actor state must already pin exactly these programs rather than being refused,
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
            Response::set_state(write_once(
                &input.pre_state,
                config_bytes(outbox_account_id, target_account_id).to_vec(),
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
    use lee_core::account::ShardData;

    use super::*;

    const BRIDGE_LOCK_ID: AccountId = AccountId::new([4; 32]);
    const OUTBOX_ID: AccountId = AccountId::new([3; 32]);
    const WRAPPED_ID: AccountId = AccountId::new([5; 32]);
    const HOLDER: AccountId = AccountId::new([6; 32]);
    const RECIPIENT: [u8; 32] = [7; 32];
    const ZONE: [u8; 32] = [8; 32];
    const AMOUNT: u128 = 1_000;

    fn config() -> ShardData {
        ShardData::try_from(config_bytes(OUTBOX_ID, WRAPPED_ID).to_vec()).expect("config fits")
    }

    fn route(outbox_account_id: AccountId, target_account_id: AccountId) -> Effect {
        Effect::Route {
            outbox_account_id,
            target_account_id,
        }
    }

    fn mint_payload(amount: u128) -> Vec<u8> {
        borsh::to_vec(&WrappedInstruction::Mint {
            recipient: RECIPIENT,
            amount,
        })
        .expect("the mint serializes")
    }

    fn target_accounts() -> Vec<ProgramShardSelector> {
        vec![
            ProgramShardSelector::new(
                wrapped_token_core::config_account_id(WRAPPED_ID),
                WRAPPED_ID,
            ),
            ProgramShardSelector::new(
                wrapped_token_core::holding_account_id(WRAPPED_ID, &RECIPIENT),
                WRAPPED_ID,
            ),
        ]
    }

    fn lock_instruction(target_account_id: AccountId) -> Instruction {
        Instruction::Lock {
            amount: AMOUNT,
            target_zone: ZONE,
            target_account_id,
            target_accounts: target_accounts(),
            payload: mint_payload(AMOUNT),
            ordinal: 0,
        }
    }

    fn accounts(outbox_program: AccountId) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(config_account_id(BRIDGE_LOCK_ID), false, BRIDGE_LOCK_ID),
            AccountMeta::native_balance(HOLDER, true),
            AccountMeta::native_balance(
                holding_account_id(BRIDGE_LOCK_ID, &HOLDER.into_value()),
                false,
            ),
            AccountMeta::native_balance(escrow_account_id(BRIDGE_LOCK_ID), false),
            AccountMeta::new(
                cross_zone_outbox_core::outbox_pda(outbox_program, BRIDGE_LOCK_ID, &ZONE, 0),
                false,
                outbox_program,
            ),
        ]
    }

    fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
        plan(
            &PlanInput {
                self_account_id: BRIDGE_LOCK_ID,
                caller_account_id: None,
                accounts,
                instruction_data: borsh::to_vec(&instruction).expect("the instruction serializes"),
            },
            instruction,
        )
    }

    #[test]
    fn a_lock_pins_its_route_before_it_moves_anything() {
        let plan = plan_for(accounts(OUTBOX_ID), lock_instruction(WRAPPED_ID));

        assert_eq!(
            plan.output().effects,
            vec![lee_core::program::ShardEffect::new(
                &AccountMeta::new(config_account_id(BRIDGE_LOCK_ID), false, BRIDGE_LOCK_ID),
                &route(OUTBOX_ID, WRAPPED_ID),
            )],
            "the chosen route must be pinned to the config"
        );
        let calls = &plan.output().chained_calls;
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0].program_account_id,
            lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID,
            "the escrow debit runs first"
        );
        assert_eq!(calls[1].program_account_id, OUTBOX_ID);
    }

    #[test]
    fn the_route_genesis_pinned_is_accepted() {
        assert_eq!(apply(route(OUTBOX_ID, WRAPPED_ID), &config()), None);
    }

    #[test]
    #[should_panic(expected = "bridge_lock only emits through the outbox it is pinned to")]
    fn an_outbox_the_config_does_not_pin_is_refused() {
        // The emission is what compensates the escrow debit. Steered to a program of the
        // caller's choosing, the balance is gone and nothing mints on the destination.
        apply(route(AccountId::new([0xAA; 32]), WRAPPED_ID), &config());
    }

    #[test]
    #[should_panic(expected = "bridge_lock only mints through the wrapped token it is pinned to")]
    fn a_mint_target_the_config_does_not_pin_is_refused() {
        apply(route(OUTBOX_ID, AccountId::new([0xBB; 32])), &config());
    }

    #[test]
    #[should_panic(expected = "config account holds an outbox and a mint target")]
    fn an_unwritten_config_authorizes_no_route() {
        apply(route(OUTBOX_ID, WRAPPED_ID), &ShardData::empty());
    }

    #[test]
    fn a_first_init_writes_the_route() {
        assert_eq!(
            apply(
                Effect::InitConfig {
                    outbox_account_id: OUTBOX_ID,
                    target_account_id: WRAPPED_ID,
                },
                &ShardData::empty()
            ),
            Some(config_bytes(OUTBOX_ID, WRAPPED_ID).to_vec())
        );
    }

    #[test]
    fn replaying_the_same_init_is_a_no_op() {
        assert_eq!(
            apply(
                Effect::InitConfig {
                    outbox_account_id: OUTBOX_ID,
                    target_account_id: WRAPPED_ID,
                },
                &config()
            ),
            Some(config_bytes(OUTBOX_ID, WRAPPED_ID).to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_a_different_route_is_refused() {
        apply(
            Effect::InitConfig {
                outbox_account_id: OUTBOX_ID,
                target_account_id: AccountId::new([0xBB; 32]),
            },
            &config(),
        );
    }

    #[test]
    #[should_panic(expected = "locked amount must equal the wrapped mint amount")]
    fn a_payload_minting_more_than_is_locked_is_refused() {
        let _plan = plan_for(
            accounts(OUTBOX_ID),
            Instruction::Lock {
                amount: AMOUNT,
                target_zone: ZONE,
                target_account_id: WRAPPED_ID,
                target_accounts: target_accounts(),
                payload: mint_payload(AMOUNT.saturating_mul(2)),
                ordinal: 0,
            },
        );
    }

    #[test]
    #[should_panic(expected = "target accounts must be the mint's config and the recipient's")]
    fn target_accounts_are_derived_from_the_proposed_target() {
        // A forged proposed target still has to name that target's own PDAs here, and the config
        // effect then refuses it.
        let _plan = plan_for(
            accounts(OUTBOX_ID),
            lock_instruction(AccountId::new([0xBB; 32])),
        );
    }

    #[test]
    #[should_panic(expected = "holder must authorize the lock")]
    fn a_lock_without_the_holder_is_refused() {
        let mut metas = accounts(OUTBOX_ID);
        metas[1] = AccountMeta::native_balance(HOLDER, false);
        let _plan = plan_for(metas, lock_instruction(WRAPPED_ID));
    }
}
