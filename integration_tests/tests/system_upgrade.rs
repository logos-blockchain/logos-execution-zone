#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext,
    config::SequencerPartialConfig,
    utils::{get_account, get_account_view, wait_for_indexer_to_catch_up, wait_until},
};
use lee::{AccountId, PrivateKey, ProgramShardSelector, PublicKey};
use lee_core::{
    account::Nonce,
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramId},
};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{self, MultiNodeTestContextConfig},
};
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;

/// Blocks between scheduling and the upgrade's height, and the approvals' lifetime.
const UPGRADE_DELAY: u64 = 5;
const APPROVAL_LIFETIME: u64 = 30;

fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        ..SequencerPartialConfig::default()
    }
}

async fn submit(
    ctx: &TestContext,
    program: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    nonces: Vec<Nonce>,
    instruction: impl borsh::BorshSerialize,
    payer: &PublicAccountPrivateInitialData,
    extra_signers: &[&PrivateKey],
) -> Result<()> {
    let message = lee::public_transaction::Message::try_new_with_fees(
        program,
        shard_selectors,
        nonces,
        instruction,
        lee::FeeDeclaration::new(
            payer.account_id,
            fee_core::market::MAX_GAS_EXEC,
            0,
            u128::MAX >> 1,
        ),
    )?;
    let mut keys = extra_signers.to_vec();
    keys.push(&payer.pub_sign_key);
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &keys);
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            witness_set,
        )))
        .await?;
    wait_until(&format!("transaction {tx_hash} to be included"), || async {
        Ok(ctx
            .sequencer_client()
            .get_transaction(tx_hash)
            .await?
            .is_some())
    })
    .await
}

/// Approvals of `proposal` by every sequencer in a two-node zone, the whole committee.
async fn committee_approvals(
    ctx: &TestContext,
    proposal: &system_upgrader_core::Proposal,
    valid_until: u64,
) -> Result<Vec<system_upgrader_core::Approval>> {
    use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};

    let committee = get_account_view(ctx, committee_selector()).await?;
    let channel_id = sequencer_stake_core::SequencerStakeConfig::from_bytes(
        committee.data.shard(programs::sequencer_stake_account_id()),
    )
    .and_then(|config| config.channel_id)
    .context("the committee config has no channel id")?;
    let message = system_upgrader_core::approval_message(channel_id, proposal, valid_until);

    [
        config::SEQUENCER_SIGNING_KEY,
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

fn committee_selector() -> ProgramShardSelector {
    let stake_program = programs::sequencer_stake_account_id();
    ProgramShardSelector::new(
        sequencer_stake_core::sequencer_stake_config_account_id(stake_program),
        stake_program,
    )
}

async fn image_id(ctx: &TestContext, program: AccountId) -> Result<ProgramId> {
    let header = get_account_view(
        ctx,
        ProgramShardSelector::new(program, PROGRAM_LOADER_ACCOUNT_ID),
    )
    .await?;
    let header = ProgramHeader::from_loader_shard(header.data.shard(PROGRAM_LOADER_ACCOUNT_ID))
        .context("no program header")?;
    Ok(header.image_id)
}

/// The new code is uploaded, the committee approves `bridge`'s upgrade and the producer schedules
/// it, and from the upgrade's height `bridge` runs it while blocks keep coming.
#[test]
async fn an_approved_system_upgrade_goes_live_at_its_height() -> Result<()> {
    let new_code = test_programs::data_writer();
    let user_elf = new_code.user_elf()?;
    let keys: Vec<PrivateKey> = (0..program_loader_core::segment_count(&user_elf))
        .map(|i| PrivateKey::try_new([0xB0_u8.wrapping_add(u8::try_from(i).unwrap()); 32]))
        .collect::<Result<_, _>>()?;
    let segment_ids: Vec<AccountId> = keys
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .collect();
    let segments = program_loader_core::build_segments(&user_elf, &segment_ids)?;

    let bridge = programs::bridge_account_id();
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            // Two sequencers: the approval threshold needs both.
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                ..MultiNodeTestContextConfig::default()
            })
            .with_sequencer_partial_config(fast_blocks()),
        )
        .build()
        .await?;

    assert_eq!(image_id(&ctx, bridge).await?, programs::bridge().id());

    // Segments link to the next one, so the chain is written tail first.
    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    for (i, segment) in segments.into_iter().enumerate().rev() {
        let mut selectors = vec![ProgramShardSelector::new(
            segment_ids[i],
            PROGRAM_LOADER_ACCOUNT_ID,
        )];
        selectors.extend(
            segment
                .next_segment
                .map(|next| ProgramShardSelector::new(next, PROGRAM_LOADER_ACCOUNT_ID)),
        );
        let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;
        submit(
            &ctx,
            PROGRAM_LOADER_ACCOUNT_ID,
            selectors,
            vec![Nonce(0), payer_nonce],
            program_loader_core::Instruction::WriteSegment {
                bytecode: segment.bytecode,
                next_segment: segment.next_segment,
            },
            &payer,
            &[&keys[i]],
        )
        .await?;
    }

    // The committee approves the upgrade, and the producer includes the approved `Schedule`.
    // Until approval tooling lands, the test hands it to the node directly.
    let now = ctx.sequencer_client().get_last_block_id().await?;
    let from_height = now.saturating_add(UPGRADE_DELAY);
    let proposal = system_upgrader_core::Proposal::Schedule {
        name: programs::BRIDGE_NAME,
        first_segment: segment_ids[0],
        from_height,
    };
    let approvals =
        committee_approvals(&ctx, &proposal, now.saturating_add(APPROVAL_LIFETIME)).await?;
    let schedule = LeeTransaction::Public(lee::PublicTransaction::new(
        lee::public_transaction::Message::try_new(
            lee_core::program::SYSTEM_UPGRADER_ACCOUNT_ID,
            vec![
                ProgramShardSelector::new(
                    system_upgrader_core::registry_account_id(),
                    lee_core::program::SYSTEM_UPGRADER_ACCOUNT_ID,
                ),
                ProgramShardSelector::new(bridge, PROGRAM_LOADER_ACCOUNT_ID),
                committee_selector(),
            ],
            vec![],
            system_upgrader_core::Instruction::Schedule {
                name: programs::BRIDGE_NAME,
                first_segment: segment_ids[0],
                from_height,
                approvals,
            },
        )?,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));
    let schedule_hash = schedule.hash();
    ctx.default_sequencer_component()
        .sequencer_handle
        .submit_system_upgrader_tx(schedule)
        .await?;
    wait_until("the Schedule to be included", || async {
        Ok(ctx
            .sequencer_client()
            .get_transaction(schedule_hash)
            .await?
            .is_some())
    })
    .await?;
    if ctx.sequencer_client().get_last_block_id().await? < from_height {
        assert_eq!(
            image_id(&ctx, bridge).await?,
            programs::bridge().id(),
            "nothing changes before the upgrade's height"
        );
    }

    wait_until("bridge to run the new code", || async {
        Ok(image_id(&ctx, bridge).await? == new_code.id())
    })
    .await?;

    // `bridge` is now the data writer: it writes the instruction into its own shard.
    let target = AccountId::new([0x5A; 32]);
    let written = vec![1_u8, 2, 3];
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;
    submit(
        &ctx,
        bridge,
        vec![ProgramShardSelector::new(target, bridge)],
        vec![payer_nonce],
        written.clone(),
        &payer,
        &[],
    )
    .await?;
    let view = get_account_view(&ctx, ProgramShardSelector::new(target, bridge)).await?;
    assert_eq!(view.data.shard(bridge).as_ref(), written.as_slice());

    let upgraded_at = ctx.sequencer_client().get_last_block_id().await?;
    wait_until("blocks to keep coming after the upgrade", || async {
        Ok(ctx.sequencer_client().get_last_block_id().await? > upgraded_at.saturating_add(2))
    })
    .await?;

    // The indexer validates every block, the upgrade's system_upgrader transactions included.
    wait_for_indexer_to_catch_up(&ctx).await?;

    Ok(())
}
