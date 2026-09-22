use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, escrow_account_id, holding_account_id,
    holding_seed, read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    native_token::custody_transfer,
    program::{
        AccountMeta, ChainedCall, LeeCall, Plan, ProgramInput, Proposed, ResolveInput,
        read_lee_call, resolve_keep, resolve_write,
    },
};
use wrapped_token_core::{Instruction as WrappedInstruction, MAX_MINT_AMOUNT};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
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
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data).write(),
        LeeCall::Resolve(input) => match resolve(&input) {
            None => resolve_keep(input),
            Some(data) => resolve_write(
                input,
                data.try_into().expect("pinned ids fit in account data"),
            ),
        },
    }
}

fn resolve(input: &ResolveInput) -> Option<Vec<u8>> {
    // `Route` ends in `Keep`, and a `Keep` is never refused for naming a foreign shard, so
    // without this the route could be "confirmed" against a shard the caller filled.
    assert_eq!(
        input.selector.program_account_id, input.self_account_id,
        "bridge_lock only resolves effects on its own shard"
    );
    let effect: Effect =
        borsh::from_slice(&input.effect_data).expect("bridge_lock wrote its own effect");

    match effect {
        Effect::Route {
            outbox_account_id,
            target_account_id,
        } => {
            let (outbox, target) = read_config(&input.pre_data)
                .expect("config account holds an outbox and a mint target");
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
        } => {
            let bytes = config_bytes(outbox_account_id, target_account_id);
            if !input.pre_data.is_empty() {
                assert_eq!(
                    *input.pre_data, bytes,
                    "bridge-lock config already pins a different outbox or mint target"
                );
            }
            Some(bytes.to_vec())
        }
    }
}

fn execute(input: &ProgramInput<Instruction>, instruction_data: Vec<u8>) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "bridge_lock is only invoked as a top-level user transaction"
    );

    match &input.instruction {
        Instruction::Lock {
            amount,
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => lock(
            input,
            instruction_data,
            *amount,
            *target_zone,
            *target_account_id,
            target_accounts,
            payload,
            *ordinal,
        ),
        Instruction::InitConfig {
            outbox_account_id,
            target_account_id,
        } => init_config(
            input,
            instruction_data,
            *outbox_account_id,
            *target_account_id,
        ),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the emission fields are passed through verbatim"
)]
fn lock(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    amount: u128,
    target_zone: [u8; 32],
    target_account_id: AccountId,
    target_accounts: &[ProgramShardSelector],
    payload: &[u8],
    ordinal: u32,
) -> Plan {
    let self_account_id = input.self_account_id;
    // Only the config input needs this program's shard.
    let [config, holder, holding, escrow, outbox] =
        <&[AccountMeta; 5]>::try_from(input.accounts.as_slice())
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
    } = decode_mint(payload)
    else {
        panic!("bridge_lock payload must be a wrapped-token mint");
    };
    assert_eq!(
        mint_amount, amount,
        "locked amount must equal the wrapped mint amount"
    );

    let mut plan = Plan::new(input, instruction_data);
    // The outbox handle's program, not a new instruction field, carries the proposed route.
    // Effects resolve before any chained call, so this lands before the debit, as the read it
    // replaces did.
    let (outbox_account_id, pinned_target) = plan
        .require(
            config,
            &Effect::Route {
                outbox_account_id: outbox.program_account_id,
                target_account_id,
            },
            Proposed::new((outbox.program_account_id, target_account_id)),
        )
        .get();

    // `target_zone` is not checkable here, so a lock aimed at a zone that will not route it
    // still burns.
    let expected_accounts = vec![
        ProgramShardSelector::new(
            wrapped_token_core::config_account_id(pinned_target),
            pinned_target,
        ),
        ProgramShardSelector::new(
            wrapped_token_core::holding_account_id(pinned_target, &recipient),
            pinned_target,
        ),
    ];
    assert_eq!(
        target_accounts,
        expected_accounts.as_slice(),
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
        outbox_account_id,
        vec![ProgramShardSelector::from(outbox)],
        &OutboxInstruction::Emit {
            target_zone,
            target_account_id: pinned_target,
            target_accounts: target_accounts.to_vec(),
            payload: payload.to_vec(),
            ordinal,
        },
    ));
    plan
}

/// Writes the outbox program and the mint target into the config PDA exactly once
/// at genesis.
fn init_config(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    outbox_account_id: AccountId,
    target_account_id: AccountId,
) -> Plan {
    let [config] = <&[AccountMeta; 1]>::try_from(input.accounts.as_slice())
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(input.self_account_id),
        "account must be the bridge-lock config PDA"
    );

    let mut plan = Plan::new(input, instruction_data);
    plan.update(
        config,
        &Effect::InitConfig {
            outbox_account_id,
            target_account_id,
        },
    );
    plan
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

    fn resolve_on(
        program_account_id: AccountId,
        pre_data: ShardData,
        effect: &Effect,
    ) -> Option<Vec<u8>> {
        resolve(&ResolveInput {
            self_account_id: BRIDGE_LOCK_ID,
            selector: ProgramShardSelector::new(
                config_account_id(BRIDGE_LOCK_ID),
                program_account_id,
            ),
            pre_data,
            effect_data: borsh::to_vec(effect).expect("the effect serializes"),
        })
    }

    fn resolve_at(pre_data: ShardData, effect: &Effect) -> Option<Vec<u8>> {
        resolve_on(BRIDGE_LOCK_ID, pre_data, effect)
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
            AccountMeta::balance(HOLDER, true),
            AccountMeta::balance(
                holding_account_id(BRIDGE_LOCK_ID, &HOLDER.into_value()),
                false,
            ),
            AccountMeta::balance(escrow_account_id(BRIDGE_LOCK_ID), false),
            AccountMeta::new(
                cross_zone_outbox_core::outbox_pda(outbox_program, BRIDGE_LOCK_ID, &ZONE, 0),
                false,
                outbox_program,
            ),
        ]
    }

    fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
        let instruction_data = borsh::to_vec(&instruction).expect("the instruction serializes");
        execute(
            &ProgramInput {
                self_account_id: BRIDGE_LOCK_ID,
                caller_account_id: None,
                accounts,
                instruction,
            },
            instruction_data,
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
        assert_eq!(resolve_at(config(), &route(OUTBOX_ID, WRAPPED_ID)), None);
    }

    #[test]
    #[should_panic(expected = "bridge_lock only emits through the outbox it is pinned to")]
    fn an_outbox_the_config_does_not_pin_is_refused() {
        // The emission is what compensates the escrow debit. Steered to a program of the
        // caller's choosing, the balance is gone and nothing mints on the destination.
        resolve_at(config(), &route(AccountId::new([0xAA; 32]), WRAPPED_ID));
    }

    #[test]
    #[should_panic(expected = "bridge_lock only mints through the wrapped token it is pinned to")]
    fn a_mint_target_the_config_does_not_pin_is_refused() {
        resolve_at(config(), &route(OUTBOX_ID, AccountId::new([0xBB; 32])));
    }

    #[test]
    #[should_panic(expected = "config account holds an outbox and a mint target")]
    fn an_unwritten_config_authorizes_no_route() {
        resolve_at(ShardData::empty(), &route(OUTBOX_ID, WRAPPED_ID));
    }

    #[test]
    #[should_panic(expected = "bridge_lock only resolves effects on its own shard")]
    fn a_route_confirmed_against_a_foreign_shard_is_refused() {
        // `Route` ends in `Keep`, so the foreign-shard write rejection never fires for it. These
        // bytes pin the real route; they are refused because whoever owns that shard chose them.
        resolve_on(
            AccountId::new([0xCC; 32]),
            config(),
            &route(OUTBOX_ID, WRAPPED_ID),
        );
    }

    #[test]
    fn a_first_init_writes_the_route() {
        assert_eq!(
            resolve_at(
                ShardData::empty(),
                &Effect::InitConfig {
                    outbox_account_id: OUTBOX_ID,
                    target_account_id: WRAPPED_ID,
                },
            ),
            Some(config_bytes(OUTBOX_ID, WRAPPED_ID).to_vec())
        );
    }

    #[test]
    fn replaying_the_same_init_is_a_no_op() {
        assert_eq!(
            resolve_at(
                config(),
                &Effect::InitConfig {
                    outbox_account_id: OUTBOX_ID,
                    target_account_id: WRAPPED_ID,
                },
            ),
            Some(config_bytes(OUTBOX_ID, WRAPPED_ID).to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "bridge-lock config already pins a different outbox or mint target")]
    fn a_reinit_with_a_different_route_is_refused() {
        resolve_at(
            config(),
            &Effect::InitConfig {
                outbox_account_id: OUTBOX_ID,
                target_account_id: AccountId::new([0xBB; 32]),
            },
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
        // The proposed target only reaches the emission through `Plan::require`, so a forged one
        // still has to name that target's own PDAs here, and the config effect then refuses it.
        let _plan = plan_for(
            accounts(OUTBOX_ID),
            lock_instruction(AccountId::new([0xBB; 32])),
        );
    }

    #[test]
    #[should_panic(expected = "holder must authorize the lock")]
    fn a_lock_without_the_holder_is_refused() {
        let mut metas = accounts(OUTBOX_ID);
        metas[1] = AccountMeta::balance(HOLDER, false);
        let _plan = plan_for(metas, lock_instruction(WRAPPED_ID));
    }
}
