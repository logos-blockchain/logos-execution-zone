pub use std::time::Duration;

pub use logos_blockchain_common_http_client::BasicAuthCredentials;
pub use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkPublicKey};
pub use logos_blockchain_zone_sdk::node_types::ChannelId;
pub use url::Url;

pub struct Config {
    pub node_url: Url,
    pub basic_auth: Option<BasicAuthCredentials>,
    pub channel_id: ChannelId,
    pub bedrock_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
    pub resubmit_interval: Duration,
}
