use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext, get_account, get_account_view, new_account, wait_for_indexer_to_catch_up,
    wait_until,
};
use lee::{AccountId, Actor};
use lee_core::{
    BlockId,
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramId, SystemProgramName},
};
use program_loader_core::LoaderActorState as _;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{self, MultiNodeTestContextConfig, SequencerPartialConfig},
};
use tokio::test;
use wallet::program_facades::program_loader::ProgramLoader;

/// Blocks between scheduling and the upgrade's activation height: room for the `Schedule` to land
/// before it even after a reorg returns it to the mempool. The approvals outlive it.
const UPGRADE_DELAY: BlockId = 40;
const APPROVAL_LIFETIME: BlockId = 60;

fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        ..SequencerPartialConfig::default()
    }
}

/// Approvals of `proposal` by every sequencer in a two-node zone, the whole committee.
async fn committee_approvals(
    ctx: &TestContext,
    proposal: &system_upgrader_core::Proposal,
    valid_until: BlockId,
) -> Result<Vec<system_upgrader_core::Approval>> {
    use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};

    let committee = get_account_view(ctx, system_upgrader_core::committee_actor()).await?;
    let channel_id = sequencer_stake_core::SequencerStakeConfig::from_bytes(
        committee
            .data
            .actor_state(programs::sequencer_stake_account_id()),
    )
    .and_then(|config| config.channel_id)
    .context("the committee config has no channel id")?;
    let message = system_upgrader_core::approval_message(channel_id, proposal, valid_until);

    [
        config::CHANNEL_SIGNING_KEY,
        *config::sequencer_signing_key_from_seed(1).to_bytes(),
    ]
    .iter()
    .map(|secret| {
        let key = SigningKey::from_bytes(secret);
        Ok(system_upgrader_core::Approval {
            signer: sequencer_stake_core::SequencerKey::new(key.verifying_key().to_bytes())
                .context("a sequencer key is a curve point")?,
            valid_until,
            signature: key.sign(&message).to_bytes().to_vec(),
        })
    })
    .collect()
}

async fn image_id(sequencer: &SequencerClient, program: AccountId) -> Result<ProgramId> {
    let header = sequencer
        .get_account_view(Actor::new(program, PROGRAM_LOADER_ACCOUNT_ID))
        .await?
        .unwrap_or_default();
    let header =
        ProgramHeader::from_loader_actor_state(header.data.actor_state(PROGRAM_LOADER_ACCOUNT_ID))
            .context("no program header")?;
    Ok(header.image_id)
}

/// A two-sequencer zone: the approval threshold needs both.
async fn two_node_zone() -> Result<TestContext> {
    MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                ..MultiNodeTestContextConfig::default()
            })
            .with_sequencer_partial_config(fast_blocks()),
        )
        .build()
        .await
}

/// Uploads `user_elf` as a segment chain; returns the segment ids, head first.
async fn upload(ctx: &mut TestContext, user_elf: &[u8]) -> Result<Vec<AccountId>> {
    let payer = ctx.existing_public_accounts()[0];
    let mut segment_ids = Vec::new();
    for _ in 0..program_loader_core::segment_count(user_elf) {
        segment_ids.push(new_account(ctx, false, None).await?);
    }
    let segments = program_loader_core::build_segments(user_elf, &segment_ids)?;

    // Segments link to the next one, so the chain is written tail first. Only segments: the
    // header stays the system program's own.
    for (segment_id, segment) in segment_ids.iter().zip(segments).rev() {
        let tx_hash = ProgramLoader(ctx.wallet())
            .write_segment(
                *segment_id,
                segment.bytecode,
                segment.next_segment,
                Some(payer),
            )
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        ctx.wallet().poll_transaction(tx_hash).await?;
    }
    Ok(segment_ids)
}

/// Hands the producer a `system_upgrader` transaction to the registry and `actors`, and waits
/// for it to be included. Until approval tooling lands, the test hands it to the node directly.
async fn submit_system_change(
    ctx: &TestContext,
    actors: impl IntoIterator<Item = Actor>,
    message: system_upgrader_core::Message,
) -> Result<()> {
    let registry = system_upgrader_core::registry_actor();
    let tx = LeeTransaction::Public(lee::PublicTransaction::new(
        lee::public_transaction::Message::try_new(
            registry,
            std::iter::once(registry).chain(actors),
            BTreeMap::new(),
            message,
        )?,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));
    let tx_hash = tx.hash();
    ctx.default_sequencer_component()
        .sequencer_handle
        .submit_transaction(tx)
        .await?;
    wait_until("the system change to be included", || async {
        Ok(ctx
            .sequencer_client()
            .get_transaction(tx_hash)
            .await?
            .is_some())
    })
    .await
}

/// Schedules `bridge`'s upgrade to the chain at `first_segment` with the committee's approvals;
/// returns its activation height.
async fn schedule_bridge_upgrade(
    ctx: &TestContext,
    first_segment: AccountId,
    image_id: ProgramId,
) -> Result<BlockId> {
    let now = ctx.sequencer_client().get_last_block_id().await?;
    let activation_height = now.saturating_add(UPGRADE_DELAY);
    let proposal = system_upgrader_core::Proposal::Schedule {
        name: programs::BRIDGE_NAME,
        first_segment,
        image_id,
        immutable: false,
        activation_height,
    };
    let approvals =
        committee_approvals(ctx, &proposal, now.saturating_add(APPROVAL_LIFETIME)).await?;
    let staging = system_upgrader_core::staging_actor(
        &programs::BRIDGE_NAME,
        &system_upgrader_core::ScheduledUpgrade {
            first_segment,
            image_id,
            immutable: false,
            activation_height,
        },
    );
    submit_system_change(
        ctx,
        [
            system_upgrader_core::committee_actor(),
            system_upgrader_core::loader_actor(&programs::BRIDGE_NAME),
            staging,
        ],
        system_upgrader_core::Message::Schedule {
            name: programs::BRIDGE_NAME,
            first_segment,
            image_id,
            immutable: false,
            activation_height,
            approvals,
        },
    )
    .await?;
    Ok(activation_height)
}

/// Waits until every sequencer in the zone runs `program` as `expected`.
async fn every_sequencer_runs(
    ctx: &TestContext,
    program: AccountId,
    expected: ProgramId,
) -> Result<()> {
    let (channel_id, _) = ctx.zones_iter().next().context("a zone")?;
    for sequencer in ctx
        .sequencer_components_iter(*channel_id)
        .context("the zone's sequencers")?
    {
        wait_until("every sequencer to run the new code", || async {
            Ok(image_id(&sequencer.sequencer_client, program).await.ok() == Some(expected))
        })
        .await?;
    }
    Ok(())
}

/// Has `program`, running the scripted guest, write into a fresh account's actor state, and
/// checks it did.
async fn run_scripted_write(ctx: &mut TestContext, program: AccountId) -> Result<()> {
    let payer = ctx.existing_public_accounts()[0];
    let target_id = new_account(ctx, false, None).await?;
    let signers = [target_id, payer];
    let nonces = signers
        .into_iter()
        .zip(ctx.wallet_mut().get_accounts_nonces(&signers).await?)
        .collect();
    let written = vec![1_u8, 2, 3];
    let target = Actor::new(target_id, program);
    let message = lee::public_transaction::Message::try_new_with_fees(
        target,
        [target],
        nonces,
        test_guest_core::Script::write(written.clone()),
        common::test_utils::test_fee_declaration(payer),
    )?;
    let keys = signers.map(|id| {
        ctx.wallet()
            .get_account_public_signing_key(id)
            .expect("the wallet holds both keys")
    });
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &keys);
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            witness_set,
        )))
        .await?;
    ctx.wallet().poll_transaction(tx_hash).await?;
    let view = get_account_view(ctx, target).await?;
    assert_eq!(view.data.actor_state(program).as_ref(), written.as_slice());
    Ok(())
}

/// The new code is uploaded, the committee approves `bridge`'s upgrade and the producer schedules
/// it, and from the block it activates in `bridge` runs it while blocks keep coming.
#[test]
async fn an_approved_system_upgrade_goes_live_at_its_height() -> Result<()> {
    let new_code = test_programs::scripted();
    let bridge = programs::bridge_account_id();
    let mut ctx = two_node_zone().await?;

    assert_eq!(
        image_id(ctx.sequencer_client(), bridge).await?,
        programs::bridge().id()
    );
    // `bridge`'s PDA holds the unissued supply; nothing in this test draws on it.
    let supply_before = get_account(&ctx, system_accounts::bridge_account_id()).await?;

    let segment_ids = upload(&mut ctx, &new_code.user_elf()?).await?;
    let activation_height = schedule_bridge_upgrade(&ctx, segment_ids[0], new_code.id()).await?;
    // Read before the height, so a chain still short of it after the read was short during it.
    let image_before = image_id(ctx.sequencer_client(), bridge).await?;
    if ctx.sequencer_client().get_last_block_id().await? < activation_height {
        assert_eq!(
            image_before,
            programs::bridge().id(),
            "nothing changes before the upgrade's height"
        );
    }

    wait_until("bridge to run the new code", || async {
        Ok(image_id(ctx.sequencer_client(), bridge).await? == new_code.id())
    })
    .await?;

    every_sequencer_runs(&ctx, bridge, new_code.id()).await?;
    assert_eq!(
        get_account(&ctx, system_accounts::bridge_account_id()).await?,
        supply_before,
        "an upgrade replaces code, not the program's accounts"
    );

    // `bridge` now runs the scripted guest: it writes what it is told into its own actor state.
    run_scripted_write(&mut ctx, bridge).await?;

    let upgraded_at = ctx.sequencer_client().get_last_block_id().await?;
    wait_until("blocks to keep coming after the upgrade", || async {
        Ok(ctx.sequencer_client().get_last_block_id().await? > upgraded_at.saturating_add(2))
    })
    .await?;

    // The indexer validates every block, the upgrade's system_upgrader transactions included.
    wait_for_indexer_to_catch_up(&ctx).await?;

    Ok(())
}

/// The committee schedules `bridge`'s upgrade and then cancels it: the chain passes the
/// activation height with `bridge` unchanged, and every block validates.
#[test]
async fn a_cancelled_system_upgrade_never_goes_live() -> Result<()> {
    let new_code = test_programs::scripted();
    let bridge = programs::bridge_account_id();
    let mut ctx = two_node_zone().await?;
    let segment_ids = upload(&mut ctx, &new_code.user_elf()?).await?;
    let activation_height = schedule_bridge_upgrade(&ctx, segment_ids[0], new_code.id()).await?;

    let now = ctx.sequencer_client().get_last_block_id().await?;
    let proposal = system_upgrader_core::Proposal::Cancel {
        name: programs::BRIDGE_NAME,
        first_segment: segment_ids[0],
        activation_height,
    };
    let approvals =
        committee_approvals(&ctx, &proposal, now.saturating_add(APPROVAL_LIFETIME)).await?;
    submit_system_change(
        &ctx,
        [system_upgrader_core::committee_actor()],
        system_upgrader_core::Message::Cancel {
            name: programs::BRIDGE_NAME,
            first_segment: segment_ids[0],
            activation_height,
            approvals,
        },
    )
    .await?;

    wait_until(
        "the chain to pass the cancelled upgrade's height",
        || async {
            Ok(ctx.sequencer_client().get_last_block_id().await?
                > activation_height.saturating_add(2))
        },
    )
    .await?;
    assert_eq!(
        image_id(ctx.sequencer_client(), bridge).await?,
        programs::bridge().id(),
        "a cancelled upgrade never applies"
    );

    // The indexer validates every block, the one at the cancelled height included.
    wait_for_indexer_to_catch_up(&ctx).await?;

    Ok(())
}

/// The committee approves installing a new system program; the producer includes the `Install`,
/// and every sequencer runs the program at its system address while every block validates.
#[test]
async fn an_approved_system_program_installs_and_runs() -> Result<()> {
    let new_code = test_programs::scripted();
    let name = SystemProgramName::new(b"installed_program");
    let program = AccountId::from_system_program_name(&name);
    let mut ctx = two_node_zone().await?;
    let segment_ids = upload(&mut ctx, &new_code.user_elf()?).await?;

    let now = ctx.sequencer_client().get_last_block_id().await?;
    let proposal = system_upgrader_core::Proposal::Install {
        name,
        first_segment: segment_ids[0],
        image_id: new_code.id(),
        immutable: false,
    };
    let approvals =
        committee_approvals(&ctx, &proposal, now.saturating_add(APPROVAL_LIFETIME)).await?;
    submit_system_change(
        &ctx,
        [
            system_upgrader_core::committee_actor(),
            system_upgrader_core::loader_actor(&name),
        ],
        system_upgrader_core::Message::Install {
            name,
            first_segment: segment_ids[0],
            image_id: new_code.id(),
            immutable: false,
            approvals,
        },
    )
    .await?;

    every_sequencer_runs(&ctx, program, new_code.id()).await?;
    run_scripted_write(&mut ctx, program).await?;

    // The indexer validates every block, the `Install` included.
    wait_for_indexer_to_catch_up(&ctx).await?;

    Ok(())
}
