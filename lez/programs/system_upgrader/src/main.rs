//! System Upgrader Program.
//!
//! Owns every system program's address as a PDA and upgrades a system program in two steps:
//! `Schedule` records the new segment chain and the block it applies from in the registry; `Apply`
//! checks and clears that record, then has the program loader point the program's header at the
//! new chain, authorized through the program's PDA seed. `Cancel` clears a pending record without
//! upgrading, and `Install` deploys a new system program the same way.

use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        AccountMeta, ChainedCall, LoaderInstruction, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, Plan,
        PlanInput, ProgramHeader, run_program,
    },
};
use system_upgrader_core::{
    Instruction, Registry, ScheduledUpgrade, SystemProgramName, registry_account_id,
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    Schedule(SystemProgramName, ScheduledUpgrade),
    Consume(SystemProgramName, ScheduledUpgrade),
    RequireMutableHeader,
    Register(SystemProgramName),
}

fn main() {
    run_program(plan, apply)
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Schedule(name, upgrade) => {
            let mut registry = Registry::from_bytes(pre_data).expect("registry decodes");
            let pending = registry
                .programs
                .get_mut(&name)
                .expect("system program is not registered");
            assert!(
                pending.is_none(),
                "system program already has a scheduled upgrade"
            );
            *pending = Some(upgrade);
            Some(registry.to_bytes())
        }
        Effect::Consume(name, upgrade) => {
            let mut registry = Registry::from_bytes(pre_data).expect("registry decodes");
            let pending = registry
                .programs
                .get_mut(&name)
                .expect("system program is not registered");
            assert_eq!(
                *pending,
                Some(upgrade),
                "the upgrade does not match the system program's schedule"
            );
            *pending = None;
            Some(registry.to_bytes())
        }
        Effect::RequireMutableHeader => {
            let header = ProgramHeader::from_loader_shard(pre_data)
                .expect("system program has no program header");
            assert!(!header.immutable, "system program is immutable");
            None
        }
        Effect::Register(name) => {
            let mut registry = Registry::from_bytes(pre_data).expect("registry decodes");
            assert!(
                registry.programs.insert(name, None).is_none(),
                "system program is already registered"
            );
            Some(registry.to_bytes())
        }
    }
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "system_upgrader may only be invoked at the top level"
    );
    match instruction {
        Instruction::Schedule {
            name,
            first_segment,
            from_height,
        } => {
            let [registry, header] = input.accounts.as_slice() else {
                panic!("Schedule requires the registry and the system program's header");
            };
            require_registry(registry);
            require_system_program(header, &name);

            let mut plan = Plan::new(input);
            plan.inspect(
                header,
                PROGRAM_LOADER_ACCOUNT_ID,
                &Effect::RequireMutableHeader,
            );
            plan.effect(
                registry,
                &Effect::Schedule(
                    name,
                    ScheduledUpgrade {
                        first_segment,
                        from_height,
                    },
                ),
            );
            plan
        }
        Instruction::Apply { name, from_height } => {
            let [registry, header, segments @ ..] = input.accounts.as_slice() else {
                panic!("Apply requires the registry, the header and the new segment chain");
            };
            require_registry(registry);
            require_system_program(header, &name);
            assert_eq!(
                header.program_account_id, PROGRAM_LOADER_ACCOUNT_ID,
                "the second account must select the system program's header"
            );
            let first_segment = segments
                .first()
                .expect("Apply requires at least one segment")
                .account_id;

            let mut plan = Plan::new(input);
            plan.block_window(from_height..);
            plan.effect(
                registry,
                &Effect::Consume(
                    name,
                    ScheduledUpgrade {
                        first_segment,
                        from_height,
                    },
                ),
            );
            plan.call(loader_call(
                &name,
                header,
                segments,
                &LoaderInstruction::UpdateHeader {
                    first_segment,
                    immutable: false,
                },
            ));
            plan
        }
        Instruction::Cancel {
            name,
            first_segment,
            from_height,
        } => {
            let [registry] = input.accounts.as_slice() else {
                panic!("Cancel requires the registry");
            };
            require_registry(registry);

            let mut plan = Plan::new(input);
            plan.effect(
                registry,
                &Effect::Consume(
                    name,
                    ScheduledUpgrade {
                        first_segment,
                        from_height,
                    },
                ),
            );
            plan
        }
        Instruction::Install {
            name,
            first_segment,
        } => {
            let [registry, header, segments @ ..] = input.accounts.as_slice() else {
                panic!("Install requires the registry, the header and the chain");
            };
            require_registry(registry);
            require_system_program(header, &name);
            assert_eq!(
                header.program_account_id, PROGRAM_LOADER_ACCOUNT_ID,
                "the second account must select the system program's header"
            );

            let mut plan = Plan::new(input);
            plan.effect(registry, &Effect::Register(name));
            plan.call(loader_call(
                &name,
                header,
                segments,
                &LoaderInstruction::CreateHeader {
                    first_segment,
                    immutable: false,
                },
            ));
            plan
        }
    }
}

/// A program loader call on the system program `name`'s header, authorized by its PDA seed.
fn loader_call(
    name: &SystemProgramName,
    header: &AccountMeta,
    segments: &[AccountMeta],
    instruction: &LoaderInstruction,
) -> ChainedCall {
    ChainedCall {
        program_account_id: PROGRAM_LOADER_ACCOUNT_ID,
        shard_selectors: std::iter::once(header)
            .chain(segments)
            .map(ProgramShardSelector::from)
            .collect(),
        instruction_data: borsh::to_vec(instruction).expect("a loader instruction serializes"),
        pda_seeds: vec![PdaSeed::for_system_program(name)],
    }
}

/// `account` must be `system_upgrader`'s registry.
fn require_registry(account: &AccountMeta) {
    assert_eq!(
        account.account_id,
        registry_account_id(),
        "account is not system_upgrader's registry"
    );
}

/// `account` must be the system program called `name`, whichever shard it selects.
fn require_system_program(account: &AccountMeta, name: &SystemProgramName) {
    assert_eq!(
        account.account_id,
        AccountId::from_system_program_name(name),
        "account is not the system program named by the instruction"
    );
}
