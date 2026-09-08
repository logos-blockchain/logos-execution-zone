//! Inscribes a non-block payload on the channel, signed with a sequencer's own
//! key, to provoke the offence slashing v1 punishes.
//!
//! The node holding that key must be stopped: two writers on one key race each
//! other, and only one can hold the turn. L1 admits an inscription only from
//! the sequencer whose turn it is, so this waits for the key's turn and offers
//! then.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use clap::Parser;
use kameo::actor::{ActorRef, Spawn as _};
use sequencer_bedrock_actor::{
    BedrockActor,
    protocol::{CheckIsOurTurn, GetChannelTipMessageId, MsgId, PublishRawInscription},
};

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
}

/// Waits for the tip to become `msg`. False if the turn ends first: L1 refused it.
async fn wait_until_tip(bedrock_ref: &ActorRef<BedrockActor>, msg: MsgId) -> Result<bool> {
    while bedrock_ref.ask(CheckIsOurTurn).await? {
        if bedrock_ref
            .ask(GetChannelTipMessageId)
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

    let bedrock_config = sequencer_bedrock_actor::config::Config {
        node_url: config.bedrock_config.node_url,
        basic_auth: config.bedrock_config.auth.map(Into::into),
        channel_id: config.bedrock_config.channel_id,
        bedrock_signing_key,
        funding_pk: config.bedrock_config.funding_key,
        priority_fee_percent: config.bedrock_config.priority_fee_percent,
        resubmit_interval: Duration::from_secs(5),
    };

    let mut mock_storage = sequencer_storage_actor::mock::MockStorageActor::default();
    mock_storage
        .expect_handle_get_zone_checkpoint_bytes()
        .returning(|_msg, _ctx| Ok(None));
    let mock_storage_ref = sequencer_storage_actor::mock::MockStorageActor::spawn(mock_storage);

    let broker_ref = kameo_actors::broker::Broker::spawn(kameo_actors::broker::Broker::new(
        kameo_actors::DeliveryStrategy::Guaranteed,
    ));

    let bedrock = BedrockActor::new(bedrock_config, mock_storage_ref, broker_ref)
        .await
        .context("Failed to setup Bedrock Actor")?;
    let bedrock_ref = BedrockActor::spawn(bedrock);

    let mut landed = 0;
    while landed < count {
        if !bedrock_ref.ask(CheckIsOurTurn).await? {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let outcome = bedrock_ref
            .ask(PublishRawInscription {
                data: payload.as_bytes().to_vec(),
            })
            .await
            .context("Failed to inscribe the payload")?;
        println!("offered non-block payload as {}", outcome.this_msg);

        // Offering is not landing, and nothing resubmits once this exits.
        if wait_until_tip(&bedrock_ref, outcome.this_msg).await? {
            landed = landed.saturating_add(1);
            println!("landed {landed}/{count}: {}", outcome.this_msg);
        } else {
            println!("not accepted, retrying on the next turn");
        }
    }

    Ok(())
}
