use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

pub mod errors;
pub mod message;
pub mod parser;
pub mod requests;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcLimitsConfig {
    /// Maximum byte size of the json payload.
    pub json_payload_max_size: ByteSize,
}

impl Default for RpcLimitsConfig {
    fn default() -> Self {
        Self {
            json_payload_max_size: ByteSize::mib(10),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcConfig {
    pub addr: String,
    pub cors_allowed_origins: Vec<String>,
    #[serde(default)]
    pub limits_config: RpcLimitsConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:3040".to_owned(),
            cors_allowed_origins: vec!["*".to_owned()],
            limits_config: RpcLimitsConfig::default(),
        }
    }
}

impl RpcConfig {
    #[must_use]
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_owned(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn with_port(port: u16) -> Self {
        Self {
            addr: format!("0.0.0.0:{port}"),
            ..Default::default()
        }
    }
}
