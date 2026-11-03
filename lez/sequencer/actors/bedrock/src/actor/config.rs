pub use std::time::Duration;

pub use logos_blockchain_zone_sdk::{
    common_http_client::BasicAuthCredentials,
    key_management_system_service::keys::{Ed25519Key, ZkPublicKey},
    node_types::ChannelId,
};
pub use url::Url;

pub struct Config {
    pub node_url: Url,
    pub basic_auth: Option<BasicAuthCredentials>,
    pub channel_id: ChannelId,
    pub channel_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
    pub resubmit_interval: Duration,
    pub stale_refund_slots: u64,
}
