use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, escrow_account_id, holding_account_id,
    holding_seed, read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    native_token::custody_transfer,
    program::{AccountMeta, ChainedCall, Plan, PlanInput, run_program, write_once},
};
use wrapped_token_core::{Instruction as WrappedInstruction, MAX_MINT_AMOUNT};

#[derive(Clone, Copy, borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    // Nothing releases an escrow, so an emission steered off the pinned route burns the
    // holder's balance with no compensating mint anywhere. This is all that stands between.
    Route {
        outbox_account_id: AccountId,
        target_account_id: AccountId,
    },
    InitConfig {
        outbox_account_id: AccountId,
        target_account_id: AccountId,
    },
}

fn main() {
    run_program(plan, apply)
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Route {
            outbox_account_id,
            target_account_id,
        } => {
            let (outbox, target) =
                read_config(pre_data).expect("config account holds an outbox and a mint target");
            assert_eq!(
                outbox, outbox_account_id,
                "bridge_lock only emits through the outbox it is pinned to"
            );
            assert_eq!(
                target, target_account_id,
                "bridge_lock only mints through the wrapped token it is pinned to"
            );
            None
        }
        // A written shard must already pin exactly these programs rather than being refused,
        // because genesis is replayed onto seeded state during multi-sequencer reconstruction.
        Effect::InitConfig {
            outbox_account_id,
            target_account_id,
        } => Some(write_once(
            pre_data,
            config_bytes(outbox_account_id, target_account_id).to_vec(),
        )),
    }
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "bridge_lock is only invoked as a top-level user transaction"
    );

    let mut plan = Plan::new(input);
    let self_account_id = input.self_account_id;
    let accounts = &input.accounts;
    match instruction {
        Instruction::Lock {
            amount,
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => lock(
            &mut plan,
            self_account_id,
            accounts,
            amount,
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        ),
        Instruction::InitConfig {
            outbox_account_id,
            target_account_id,
        } => init_config(
            &mut plan,
            self_account_id,
            accounts,
            outbox_account_id,
            target_account_id,
        ),
    }
    plan
}

#[expect(
    clippy::too_many_arguments,
    reason = "the emission fields are passed through verbatim"
)]
fn lock(
    plan: &mut Plan,
    self_account_id: AccountId,
    accounts: &[AccountMeta],
    amount: u128,
    target_zone: [u8; 32],
    target_account_id: AccountId,
    target_accounts: Vec<ProgramShardSelector>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // Only the config input needs this program's shard.
    let [config, holder, holding, escrow, outbox] = <&[AccountMeta; 5]>::try_from(accounts)
        .expect("Lock requires config, holder, holding, escrow, and outbox accounts");

    // Pinned rather than caller-named: chaining elsewhere would debit the escrow
    // and leave no record of what it was for.
    assert_eq!(
        config.account_id,
        config_account_id(self_account_id),
        "first account must be the bridge-lock config PDA"
    );

    // Value conservation: the escrow debit is only sound if the message mints what it locks.
    let WrappedInstruction::Mint {
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

    // The outbox handle's program, not a new instruction field, carries the proposed route.
    // Effects apply before any chained call, so this lands before the debit, as the read it
    // replaces did.
    plan.effect(
        config,
        &Effect::Route {
            outbox_account_id: outbox.program_account_id,
            target_account_id,
        },
    );

    // `target_zone` is not checkable here, so a lock aimed at a zone that will not route it
    // still burns.
    let expected_accounts = vec![
        ProgramShardSelector::new(
            wrapped_token_core::config_account_id(target_account_id),
            target_account_id,
        ),
        ProgramShardSelector::new(
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

    assert!(holder.is_authorized, "holder must authorize the lock");
    // The signature gates the debit; the derivation pins the debit target to a
    // genuine bridge-lock holding.
    assert_eq!(
        holding.account_id,
        holding_account_id(self_account_id, &holder.account_id.into_value()),
        "third account must be the holder's bridge-lock holding PDA"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(self_account_id),
        "fourth account must be the escrow PDA"
    );

    plan.call(custody_transfer(
        holding.account_id,
        holding_seed(&holder.account_id.into_value()),
        escrow.account_id,
        amount,
    ));
    plan.call(ChainedCall::new(
        outbox.program_account_id,
        vec![ProgramShardSelector::from(outbox)],
        &OutboxInstruction::Emit {
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        },
    ));
}

/// Writes the outbox program and the mint target into the config PDA exactly once
/// at genesis.
fn init_config(
    plan: &mut Plan,
    self_account_id: AccountId,
    accounts: &[AccountMeta],
    outbox_account_id: AccountId,
    target_account_id: AccountId,
) {
    let [config] =
        <&[AccountMeta; 1]>::try_from(accounts).expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(self_account_id),
        "account must be the bridge-lock config PDA"
    );

    plan.effect(
        config,
        &Effect::InitConfig {
            outbox_account_id,
            target_account_id,
        },
    );
}

/// Decodes the cross-zone payload (borsh bytes) into the wrapped-token instruction it carries.
fn decode_mint(payload: &[u8]) -> WrappedInstruction {
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
