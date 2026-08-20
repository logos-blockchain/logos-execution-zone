//! Source of the channel's current accredited key set, read from L1. Retained
//! for future ChannelConfig-signature work; not currently consumed by the
//! gossip mesh.
//!
//! FIXME: `NodeKeysProvider` will be replaced by an L2 Join/Leave-derived provider in a follow-up.
//! The related PR is <https://github.com/logos-blockchain/logos-execution-zone/pull/653>.

use std::{collections::HashSet, future::Future};

use anyhow::{Context as _, Result};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_key_management_system_service::keys::Ed25519PublicKey;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
};

use crate::config::BedrockConfig;

pub trait AccreditedKeysProvider: Send + 'static {
    /// The channel's current accredited Ed25519 keys.
    ///
    /// An empty set is valid, meaning that the channel does not exist yet.
    fn accredited_keys(&self) -> impl Future<Output = Result<HashSet<[u8; 32]>>> + Send;
}

/// Reads accredited keys from the bedrock node's channel state, on its own
/// HTTP connection (no coupling to the publisher's drive task).
pub struct NodeKeysProvider {
    node: NodeHttpClient,
    channel_id: ChannelId,
}

impl NodeKeysProvider {
    #[must_use]
    pub fn new(config: &BedrockConfig) -> Self {
        let node = NodeHttpClient::new(
            CommonHttpClient::new(config.auth.clone().map(Into::into)),
            config.node_url.clone(),
        );
        Self {
            node,
            channel_id: config.channel_id,
        }
    }
}

impl AccreditedKeysProvider for NodeKeysProvider {
    async fn accredited_keys(&self) -> Result<HashSet<[u8; 32]>> {
        let state = self
            .node
            .channel_state(self.channel_id)
            .await
            .context("Failed to read channel state for accredited keys")?;

        Ok(state
            .map(|state| {
                state
                    .accredited_keys
                    .iter()
                    .map(Ed25519PublicKey::to_bytes)
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Fixed key set, for tests.
pub struct StaticKeysProvider(pub HashSet<[u8; 32]>);

impl AccreditedKeysProvider for StaticKeysProvider {
    async fn accredited_keys(&self) -> Result<HashSet<[u8; 32]>> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_returns_its_set() {
        let keys = HashSet::from([[1; 32], [2; 32]]);
        let provider = StaticKeysProvider(keys.clone());
        assert_eq!(provider.accredited_keys().await.unwrap(), keys);
    }
}
