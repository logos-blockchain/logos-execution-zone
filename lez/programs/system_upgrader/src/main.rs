//! System Upgrader Program.
//!
//! Owns every system program's address as a PDA and upgrades a system program in two steps:
//! `Schedule` records the new segment chain and the block it applies from in the registry; `Apply`
//! checks and clears that record, then has the program loader point the program's header at the
//! new chain, authorized through the program's PDA seed. `Cancel` clears a pending record without
//! upgrading, and `Install` deploys a new system program the same way. `Schedule`, `Cancel` and
//! `Install` carry the sequencer committee's approvals.

use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        AccountMeta, ChainedCall, LoaderInstruction, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, Plan,
        PlanInput, ProgramHeader, run_program,
    },
};
use sequencer_stake_core::{
    SequencerKey, SequencerStakeConfig,
    ed25519_dalek::{Signature, VerifyingKey},
    sequencer_stake_account_id, sequencer_stake_config_account_id, slash_approval_threshold,
};
use system_upgrader_core::{
    Approval, Instruction, Proposal, Registry, ScheduledUpgrade, SystemProgramName,
    approval_message, registry_account_id,
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    Schedule(SystemProgramName, ScheduledUpgrade),
    Consume(SystemProgramName, ScheduledUpgrade),
    RequireMutableHeader,
    RequireApprovals {
        proposal: Proposal,
        approvals: Vec<Approval>,
    },
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
        Effect::RequireApprovals {
            proposal,
            approvals,
        } => {
            let config =
                SequencerStakeConfig::from_bytes(pre_data).expect("committee config decodes");
            verify_approvals(&config, &proposal, &approvals);
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
            approvals,
        } => {
            let [registry, header, committee] = input.accounts.as_slice() else {
                panic!(
                    "Schedule requires the registry, the system program's header and the committee"
                );
            };
            require_registry(registry);
            require_system_program(header, &name);

            let mut plan = Plan::new(input);
            require_approvals(
                &mut plan,
                committee,
                Proposal::Schedule {
                    name,
                    first_segment,
                    from_height,
                },
                approvals,
            );
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
            approvals,
        } => {
            let [registry, committee] = input.accounts.as_slice() else {
                panic!("Cancel requires the registry and the committee");
            };
            require_registry(registry);

            let mut plan = Plan::new(input);
            require_approvals(
                &mut plan,
                committee,
                Proposal::Cancel {
                    name,
                    first_segment,
                    from_height,
                },
                approvals,
            );
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
            approvals,
        } => {
            let [registry, committee, header, segments @ ..] = input.accounts.as_slice() else {
                panic!("Install requires the registry, the committee, the header and the chain");
            };
            require_registry(registry);
            require_system_program(header, &name);
            assert_eq!(
                header.program_account_id, PROGRAM_LOADER_ACCOUNT_ID,
                "the third account must select the system program's header"
            );

            let mut plan = Plan::new(input);
            require_approvals(
                &mut plan,
                committee,
                Proposal::Install {
                    name,
                    first_segment,
                },
                approvals,
            );
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

/// Guards the committee config with the approvals, checked in `apply`, and ends the transaction's
/// window at the earliest approval's `valid_until`: every approval it carries must still be valid.
fn require_approvals(
    plan: &mut Plan,
    committee: &AccountMeta,
    proposal: Proposal,
    approvals: Vec<Approval>,
) {
    let stake_program = sequencer_stake_account_id();
    assert_eq!(
        committee.account_id,
        sequencer_stake_config_account_id(stake_program),
        "account is not the sequencer committee's config"
    );
    let valid_until = approvals
        .iter()
        .map(|approval| approval.valid_until)
        .min()
        .expect("a change requires approvals");
    plan.block_window(..valid_until.saturating_add(1));
    plan.inspect(
        committee,
        stake_program,
        &Effect::RequireApprovals {
            proposal,
            approvals,
        },
    );
}

/// The same rules `sequencer_stake`'s `Slash` applies to its approvals.
fn verify_approvals(config: &SequencerStakeConfig, proposal: &Proposal, approvals: &[Approval]) {
    let channel_id = config
        .channel_id
        .expect("genesis sets the channel id before any stake exists");

    let mut approvers: Vec<SequencerKey> = Vec::with_capacity(approvals.len());
    for approval in approvals {
        assert!(
            config.is_accredited_committee_member(&approval.signer),
            "approval from a key the committee does not accredit"
        );
        assert!(
            !approvers.contains(&approval.signer),
            "the same key approved twice"
        );

        let verifying_key = VerifyingKey::from_bytes(&approval.signer.to_bytes())
            .expect("a SequencerKey is a valid Ed25519 public key");
        let signature = Signature::from_slice(&approval.signature)
            .expect("approval signature should be 64 bytes");
        verifying_key
            .verify_strict(
                &approval_message(channel_id, proposal, approval.valid_until),
                &signature,
            )
            .expect("approval signature should verify against its signer");

        approvers.push(approval.signer);
    }

    assert!(
        approvers.len() >= slash_approval_threshold(config.accredited_committee_members_count()),
        "the change carries fewer approvals than the threshold"
    );
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
