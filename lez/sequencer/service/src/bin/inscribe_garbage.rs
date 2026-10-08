//! Inscribes an offending payload on the channel, signed with a sequencer's own
//! key, to provoke an offence slashing punishes.
//!
//! The node holding that key must be stopped: two writers on one key race each
//! other, and only one can hold the turn. L1 admits an inscription only from
//! the sequencer whose turn it is, so this waits for the key's turn and offers
//! then.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use clap::Parser;
use common::block::Block;
use kameo::{
    Actor,
    actor::{ActorRef, Spawn as _},
    message::{Context, Message},
};
use sequencer_bedrock_actor::{
    BedrockActor,
    protocol::{
        ChannelEntry, ChannelEvent, ChannelEventKind, ChannelId, CheckIsOurTurn,
        GetChannelTipMessageId, InitializeChannelPublisher, MsgId, PublishRawInscription,
        PublisherEvent, ViewChange,
    },
};
use sequencer_storage_actor::mock::MockStorageActor;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(name = "config")]
    config_path: PathBuf,
    /// Home holding the `bedrock_signing_key` to sign with, matching the
    /// sequencer's --home.
    #[clap(long)]
    home: Option<PathBuf>,
    /// Payload bytes; anything that does not decode as a block will do.
    #[clap(long, default_value = "not a block")]
    payload: String,
    /// Stop after this many inscriptions land.
    #[clap(long, default_value_t = 1)]
    count: usize,
    /// Inscribe a block on the latest channel block whose transaction omits its fee.
    #[clap(long, conflicts_with = "wrong_id")]
    invalid_block: bool,
    /// Inscribe a block on the latest channel block that skips ahead in height.
    #[clap(long)]
    wrong_id: bool,
}

#[derive(Actor, Default)]
struct BlockWatcherActor {
    latest: Option<Block>,
    finalized: Option<Block>,
    view: Option<Block>,
}

impl Message<ChannelEvent> for BlockWatcherActor {
    type Reply = ();

    async fn handle(&mut self, msg: ChannelEvent, _ctx: &mut Context<Self, Self::Reply>) {
        let ChannelEventKind::Publisher(publisher) = msg.event else {
            return;
        };
        let PublisherEvent::Update(update) = &*publisher else {
            return;
        };

        self.finalized = highest(self.finalized.iter().chain(blocks_of(&update.finalized)));
        // A conflict replaces the view, so its orphaned blocks no longer count.
        self.view = match &update.view {
            ViewChange::Extension(adopted) => highest(self.view.iter().chain(blocks_of(adopted))),
            ViewChange::Conflict { canonical, .. } => highest(blocks_of(canonical)),
        };
        self.latest = highest(self.finalized.iter().chain(&self.view));
    }
}

struct GetLatestBlock;

impl Message<GetLatestBlock> for BlockWatcherActor {
    type Reply = Option<Block>;

    async fn handle(
        &mut self,
        _msg: GetLatestBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.latest.clone()
    }
}

/// The block in `blocks` with the highest id.
fn highest<'block>(blocks: impl Iterator<Item = &'block Block>) -> Option<Block> {
    blocks.max_by_key(|block| block.header.block_id).cloned()
}

/// The blocks `entries` carry.
fn blocks_of(entries: &[ChannelEntry]) -> impl Iterator<Item = &Block> {
    entries.iter().filter_map(|entry| entry.block.as_ref())
}

/// A block at `block_id` on `parent`, signed with a fresh block key.
fn block_on(
    parent: &Block,
    block_id: u64,
    transactions: Vec<common::transaction::LeeTransaction>,
) -> Vec<u8> {
    let block =
        common::test_utils::produce_dummy_block(block_id, Some(parent.header.hash), transactions);
    let block = common::block::HashableBlockData::from(block)
        .into_pending_block(&lee::PrivateKey::new_os_random());
    borsh::to_vec(&block).expect("a block should serialize")
}

/// Waits for the tip to become `msg`. False if the turn ends first: L1 refused it.
async fn wait_until_tip(
    bedrock_ref: &ActorRef<BedrockActor<MockStorageActor>>,
    channel_id: ChannelId,
    msg: MsgId,
) -> Result<bool> {
    while bedrock_ref.ask(CheckIsOurTurn { channel_id }).await? {
        if bedrock_ref
            .ask(GetChannelTipMessageId { channel_id })
            .await
            .context("Failed to read the channel tip")?
            == Some(msg)
        {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(false)
}

#[tokio::main]
#[expect(
    clippy::print_stdout,
    reason = "the inscription ids on stdout are this binary's output"
)]
async fn main() -> Result<()> {
    env_logger::init();
    let Args {
        config_path,
        home,
        payload,
        count,
        invalid_block,
        wrong_id,
    } = Args::parse();

    let config = sequencer_service::SequencerConfig::from_path(&config_path)?;
    let home = home.unwrap_or(config.home);
    let bedrock_signing_key =
        sequencer_core::load_or_create_signing_key(&home.join("bedrock_signing_key"))
            .context("Failed to load the bedrock signing key")?;
    println!(
        "signing as {}",
        hex::encode(bedrock_signing_key.public_key().to_bytes())
    );

    let channel_id = config.bedrock_config.channel_id;
    let broker_ref = kameo_actors::broker::Broker::spawn(kameo_actors::broker::Broker::new(
        kameo_actors::DeliveryStrategy::Guaranteed,
    ));

    let watcher = BlockWatcherActor::spawn(BlockWatcherActor::default());
    broker_ref
        .tell(kameo_actors::broker::Subscribe {
            topic: glob::Pattern::new(&format!("channel/{channel_id}/**"))
                .expect("a valid topic pattern"),
            recipient: watcher.clone().recipient(),
        })
        .await
        .context("Failed to follow the channel")?;

    let mut storage = MockStorageActor::default();
    storage
        .expect_handle_get_zone_anchor()
        .returning(|_msg, _ctx| Ok(None));
    let storage_ref = MockStorageActor::spawn(storage);

    let bedrock_ref = BedrockActor::spawn(sequencer_bedrock_actor::actor::Args {
        node_url: config.bedrock_config.node_url,
        basic_auth: config.bedrock_config.auth.map(Into::into),
        channel_id,
        storage_ref,
        broker_ref,
    });
    bedrock_ref
        .ask(InitializeChannelPublisher {
            channel_id,
            bedrock_signing_key,
            funding_pk: config.bedrock_config.funding_key,
            priority_fee_percent: config.bedrock_config.priority_fee_percent,
            resubmit_interval: Duration::from_secs(5),
        })
        .await
        .context("Failed to initialize Bedrock channel publisher")?;

    let mut landed = 0;
    while landed < count {
        if !bedrock_ref.ask(CheckIsOurTurn { channel_id }).await? {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let data = if invalid_block || wrong_id {
            let parent = watcher.ask(GetLatestBlock).await?;
            let Some(parent) = parent else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            let next = parent.header.block_id.saturating_add(1);
            println!("building on block {}", parent.header.block_id);
            if invalid_block {
                block_on(
                    &parent,
                    next,
                    vec![common::test_utils::produce_dummy_empty_transaction()],
                )
            } else {
                block_on(&parent, next.saturating_add(4), vec![])
            }
        } else {
            payload.as_bytes().to_vec()
        };
        let outcome = bedrock_ref
            .ask(PublishRawInscription { channel_id, data })
            .await
            .context("Failed to inscribe the payload")?;
        println!("offered the payload as {}", outcome.this_msg);

        // Offering is not landing, and nothing resubmits once this exits.
        if wait_until_tip(&bedrock_ref, channel_id, outcome.this_msg).await? {
            landed = landed.saturating_add(1);
            println!("landed {landed}/{count}: {}", outcome.this_msg);
        } else {
            println!("not accepted, retrying on the next turn");
        }
    }

    Ok(())
}
