//! Builtin Loader Program.
//!
//! Owns every system builtin's address as a PDA and upgrades a builtin in two steps: `Schedule`
//! records the new segment chain and the block it applies from in the builtin's account (this
//! program's shard); `Apply` checks and clears that record, then has the program loader point the
//! builtin's header at the new chain, authorized through the builtin's PDA seed.

use builtin_loader_core::{Instruction, ScheduledUpgrade};
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        AccountMeta, ChainedCall, LoaderInstruction, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, Plan,
        PlanInput, run_program,
    },
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    Schedule(ScheduledUpgrade),
    Consume(ScheduledUpgrade),
}

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    Some(match effect {
        Effect::Schedule(upgrade) => {
            assert!(
                pre_data.is_empty(),
                "builtin already has a scheduled upgrade"
            );
            upgrade.to_bytes()
        }
        Effect::Consume(upgrade) => {
            assert_eq!(
                ScheduledUpgrade::from_bytes(pre_data),
                Some(upgrade),
                "the upgrade does not match the builtin's schedule"
            );
            Vec::new()
        }
    })
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "builtin_loader may only be invoked at the top level"
    );
    match instruction {
        Instruction::Schedule {
            name,
            first_segment,
            from_height,
        } => {
            let [schedule] = input.accounts.as_slice() else {
                panic!("Schedule requires exactly the builtin's schedule account");
            };
            require_builtin(schedule, &name);

            let mut plan = Plan::new(input);
            plan.effect(
                schedule,
                &Effect::Schedule(ScheduledUpgrade {
                    first_segment,
                    from_height,
                }),
            );
            plan
        }
        Instruction::Apply { name, from_height } => {
            let [schedule, header, segments @ ..] = input.accounts.as_slice() else {
                panic!("Apply requires the schedule, the header and the new segment chain");
            };
            require_builtin(schedule, &name);
            require_builtin(header, &name);
            assert_eq!(
                header.program_account_id, PROGRAM_LOADER_ACCOUNT_ID,
                "the second account must select the builtin's header"
            );
            let first_segment = segments
                .first()
                .expect("Apply requires at least one segment")
                .account_id;

            let mut plan = Plan::new(input);
            plan.block_window(from_height..);
            plan.effect(
                schedule,
                &Effect::Consume(ScheduledUpgrade {
                    first_segment,
                    from_height,
                }),
            );
            plan.call(ChainedCall {
                program_account_id: PROGRAM_LOADER_ACCOUNT_ID,
                shard_selectors: std::iter::once(header)
                    .chain(segments)
                    .map(ProgramShardSelector::from)
                    .collect(),
                instruction_data: borsh::to_vec(&LoaderInstruction::UpdateHeader {
                    first_segment,
                    immutable: false,
                })
                .expect("a loader instruction serializes"),
                pda_seeds: vec![PdaSeed::for_builtin(&name)],
            });
            plan
        }
    }
}

/// `account` must be the builtin called `name`, whichever shard it selects.
fn require_builtin(account: &AccountMeta, name: &[u8]) {
    assert_eq!(
        account.account_id,
        AccountId::from_builtin_program_name(name),
        "account is not the builtin named by the instruction"
    );
}
