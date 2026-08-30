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
use sequencer_core::block_publisher::{BlockPublisherTrait as _, MsgId, ZoneSdkPublisher};

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
async fn wait_until_tip(publisher: &ZoneSdkPublisher, msg: MsgId) -> Result<bool> {
    while publisher.is_our_turn() {
        if publisher
            .channel_tip_message()
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
    let home = home.unwrap_or_else(|| config.home.clone());
    let key = sequencer_core::load_or_create_signing_key(&home.join("bedrock_signing_key"))
        .context("Failed to load the bedrock signing key")?;
    println!("signing as {}", hex::encode(key.public_key().to_bytes()));

    let publisher = ZoneSdkPublisher::new(
        &config.bedrock_config,
        key,
        Duration::from_secs(5),
        None,
        Box::new(|_update| Box::pin(async {})),
    )
    .await
    .context("Failed to open a publisher for this key")?;

    let mut landed = 0;
    while landed < count {
        if !publisher.is_our_turn() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let outcome = publisher
            .publish_raw_inscription(payload.as_bytes().to_vec())
            .await
            .context("Failed to inscribe the payload")?;
        println!("offered non-block payload as {}", outcome.this_msg);

        // Offering is not landing, and nothing resubmits once this exits.
        if wait_until_tip(&publisher, outcome.this_msg).await? {
            landed = landed.saturating_add(1);
            println!("landed {landed}/{count}: {}", outcome.this_msg);
        } else {
            println!("not accepted, retrying on the next turn");
        }
    }

    Ok(())
}
