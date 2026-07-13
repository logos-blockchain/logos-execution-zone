use std::time::Duration;

use common::{block::Block, transaction::LeeTransaction};
use cross_zone::{build_dispatch_from_emission, extract_emission};
use futures::StreamExt as _;
use lee::PublicKey;
use lee_core::program::ProgramId;
use log::{debug, error, info, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
use mempool::MemPoolHandle;

use crate::{
    TransactionOrigin,
    config::{BedrockConfig, CrossZoneConfig},
};

/// Spawns one watcher task per configured peer.
///
/// Each task reads the peer's finalized blocks from Bedrock, recognizes outbound
/// messages addressed to this zone, and injects the matching inbox dispatch as a
/// sequencer-origin transaction into the local mempool.
pub fn spawn_watchers(
    bedrock_config: &BedrockConfig,
    cross_zone: &CrossZoneConfig,
    poll_interval: Duration,
    mempool_handle: &MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) {
    let self_zone: [u8; 32] = *bedrock_config.channel_id.as_ref();

    for peer in cross_zone.peers.clone() {
        let node = NodeHttpClient::new(
            CommonHttpClient::new(bedrock_config.auth.clone().map(Into::into)),
            bedrock_config.node_url.clone(),
        );
        let expected_pubkey = peer.expected_block_signing_pubkey.map(|bytes| {
            PublicKey::try_new(bytes).expect("configured peer block-signing pubkey is a valid key")
        });
        tokio::spawn(watch_peer(
            ZoneIndexer::new(ChannelId::from(peer.channel_id), node),
            peer.channel_id,
            peer.allowed_targets,
            expected_pubkey,
            self_zone,
            poll_interval,
            mempool_handle.clone(),
        ));
    }
}

#[expect(
    clippy::infinite_loop,
    reason = "the peer watcher runs for the lifetime of the sequencer process"
)]
async fn watch_peer(
    zone_indexer: ZoneIndexer<NodeHttpClient>,
    peer_zone: [u8; 32],
    allowed_targets: Vec<ProgramId>,
    expected_pubkey: Option<PublicKey>,
    self_zone: [u8; 32],
    poll_interval: Duration,
    mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) {
    info!(
        "Cross-zone watcher started for peer {}",
        hex::encode(peer_zone)
    );

    let mut cursor = None;
    loop {
        let stream = match zone_indexer.next_messages(cursor).await {
            Ok(stream) => stream,
            Err(err) => {
                error!(
                    "Watcher next_messages failed for peer {}: {err}",
                    hex::encode(peer_zone)
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };
        let mut stream = std::pin::pin!(stream);

        while let Some((msg, slot)) = stream.next().await {
            let zone_block = match msg {
                ZoneMessage::Block(block) => block,
                ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => continue,
            };
            match borsh::from_slice::<Block>(&zone_block.data) {
                Ok(block) => {
                    debug!(
                        "Watcher observed finalized peer {} block {}",
                        hex::encode(peer_zone),
                        block.header.block_id
                    );
                    // Reject blocks not signed by the pinned peer key (equivocation):
                    // the channel signer is authenticated by the zone-sdk, but that
                    // does not prove the peer's honest sequencer produced the block.
                    if expected_pubkey
                        .as_ref()
                        .is_some_and(|pk| !block.is_signed_by(pk))
                    {
                        warn!(
                            "Watcher dropping peer {} block {}: block-signing key does not match the pinned key",
                            hex::encode(peer_zone),
                            block.header.block_id
                        );
                    } else {
                        deliver_block(
                            &block,
                            peer_zone,
                            self_zone,
                            &allowed_targets,
                            &mempool_handle,
                        )
                        .await;
                    }
                }
                Err(err) => error!("Watcher failed to deserialize peer block: {err}"),
            }
            cursor = Some(slot);
        }

        // Stream ended (caught up to the peer's last finalized block); poll again.
        tokio::time::sleep(poll_interval).await;
    }
}

/// Scans one peer block for outbound messages and injects a dispatch per match.
async fn deliver_block(
    block: &Block,
    peer_zone: [u8; 32],
    self_zone: [u8; 32],
    allowed_targets: &[ProgramId],
    mempool_handle: &MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) {
    for (index, tx) in block.body.transactions.iter().enumerate() {
        let LeeTransaction::Public(public_tx) = tx else {
            continue;
        };
        let message = public_tx.message();
        let Some(emission) = extract_emission(message.program_id, &message.instruction_data) else {
            continue;
        };

        if emission.target_zone != self_zone {
            continue;
        }
        if !allowed_targets.contains(&emission.target_program_id) {
            warn!(
                "Watcher dropping message to disallowed target from peer {}",
                hex::encode(peer_zone)
            );
            continue;
        }

        let dispatch = build_dispatch_from_emission(
            peer_zone,
            block.header.block_id,
            u32::try_from(index).unwrap_or(u32::MAX),
            message.program_id,
            emission.target_program_id,
            &emission.target_accounts,
            emission.payload,
        );

        match mempool_handle
            .push((
                TransactionOrigin::Sequencer,
                LeeTransaction::Public(dispatch),
            ))
            .await
        {
            Ok(()) => info!(
                "Watcher injected cross-zone dispatch from peer {} block {} tx {}",
                hex::encode(peer_zone),
                block.header.block_id,
                index
            ),
            Err(err) => error!("Watcher failed to enqueue inbox dispatch: {err}"),
        }
    }
}
