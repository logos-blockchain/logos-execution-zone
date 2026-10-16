//! System Upgrader Program.
//!
//! Owns every system program's address as a PDA and upgrades a system program in two steps:
//! `Schedule` has the program loader validate the new segment chain into a staging header, and
//! records the chain and the block it activates in in the registry; `Apply`, in that block,
//! checks and clears that record, then has the program loader point the program's header at the
//! new chain, authorized through the program's PDA seed. `Cancel` clears a pending record without
//! upgrading, and `Install` deploys a new system program the same way. `Schedule`, `Cancel` and
//! `Install` carry the sequencer committee's approvals, which `sequencer_stake` verifies. Every
//! message is handled at the registry's actor.

use lee_core::program::{PdaSeed, ReceiveInput, Response, SyncMessage};
use program_loader_core::Message as LoaderMessage;
use sequencer_stake_core::Message as StakeMessage;
use system_upgrader_core::{
    APPROVAL_DOMAIN, Message, Registry, ScheduledUpgrade, SystemProgramName, committee_actor,
    loader_actor, registry_account_id, staging_actor, staging_seed,
};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    assert!(
        input.from.is_none(),
        "system_upgrader may only be invoked at the top level"
    );
    assert_eq!(
        input.receiver.account_id,
        registry_account_id(),
        "system_upgrader messages are handled at its registry"
    );
    let mut registry = Registry::from_bytes(&input.pre_state).expect("registry decodes");
    let approval_check = message.proposal().map(|(proposal, approvals)| {
        SyncMessage::new(
            committee_actor(),
            &StakeMessage::VerifyApprovals {
                domain: APPROVAL_DOMAIN,
                payload: proposal.to_bytes(),
                approvals: approvals.to_vec(),
            },
        )
    });

    let response = match message {
        Message::Schedule {
            name,
            first_segment,
            image_id,
            activation_height,
            ..
        } => {
            assert!(
                registry
                    .programs
                    .values()
                    .flatten()
                    .all(|upgrade| upgrade.activation_height != activation_height),
                "an upgrade is already scheduled at this height"
            );
            let pending = pending_mut(&mut registry, &name);
            assert!(
                pending.is_none(),
                "system program already has a scheduled upgrade"
            );
            let upgrade = ScheduledUpgrade {
                first_segment,
                image_id,
                activation_height,
            };
            *pending = Some(upgrade);
            // The loader validates the chain and checks its image ID is the approved one now, so
            // `Apply` can't fail.
            Response::set_state(registry.to_bytes())
                .block_window(..activation_height)
                .send(
                    SyncMessage::new(
                        staging_actor(&name, &upgrade),
                        &LoaderMessage::CreateHeaderOf {
                            first_segment,
                            image_id,
                            immutable: false,
                        },
                    )
                    .with_pda_seeds([staging_seed(&name, &upgrade)]),
                )
        }
        Message::Apply {
            name,
            activation_height,
        } => {
            let upgrade = pending_mut(&mut registry, &name)
                .take()
                .expect("system program has no scheduled upgrade");
            assert_eq!(
                upgrade.activation_height, activation_height,
                "the upgrade does not match the system program's schedule"
            );
            Response::set_state(registry.to_bytes())
                .try_block_window(activation_height..activation_height.saturating_add(1))
                .expect("a one-block window is valid")
                .send(loader_message(
                    &name,
                    &LoaderMessage::UpdateHeader {
                        first_segment: upgrade.first_segment,
                        immutable: false,
                    },
                ))
        }
        Message::Cancel {
            name,
            first_segment,
            activation_height,
            ..
        } => {
            let pending = pending_mut(&mut registry, &name);
            assert!(
                pending.is_some_and(|upgrade| upgrade.first_segment == first_segment
                    && upgrade.activation_height == activation_height),
                "the upgrade does not match the system program's schedule"
            );
            *pending = None;
            // Before the upgrade's block, which must carry its `Apply`: its producer has no choice.
            Response::set_state(registry.to_bytes()).block_window(..activation_height)
        }
        Message::Install {
            name,
            first_segment,
            image_id,
            ..
        } => {
            assert!(
                registry.programs.insert(name, None).is_none(),
                "system program is already registered"
            );
            Response::set_state(registry.to_bytes()).send(loader_message(
                &name,
                &LoaderMessage::CreateHeaderOf {
                    first_segment,
                    image_id,
                    immutable: false,
                },
            ))
        }
    };
    match approval_check {
        Some(check) => response.send(check),
        None => response,
    }
}

/// The registry entry for `name`, which must be registered.
fn pending_mut<'registry>(
    registry: &'registry mut Registry,
    name: &SystemProgramName,
) -> &'registry mut Option<ScheduledUpgrade> {
    registry
        .programs
        .get_mut(name)
        .expect("system program is not registered")
}

/// A program loader message to the system program `name`'s header, authorized by its PDA seed.
fn loader_message(name: &SystemProgramName, message: &LoaderMessage) -> SyncMessage {
    SyncMessage::new(loader_actor(name), message)
        .with_pda_seeds([PdaSeed::for_system_program(name)])
}
