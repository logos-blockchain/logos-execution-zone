use crate::config::ClientConfig;

#[cfg(not(any(feature = "backend-http", feature = "backend-module")))]
compile_error!("enable one of the features `backend-http` or `backend-module`");

#[cfg(feature = "backend-module")]
pub type NodeClient = logos_blockchain_zone_sdk_module_backend::NodeModuleClient;

#[cfg(feature = "backend-module")]
#[must_use]
pub fn node_client(config: &ClientConfig) -> NodeClient {
    NodeClient::bind(config.module_name())
}

#[cfg(not(feature = "backend-module"))]
pub type NodeClient = logos_blockchain_zone_sdk::adapter::NodeHttpClient;

#[cfg(not(feature = "backend-module"))]
#[must_use]
pub fn node_client(config: &ClientConfig) -> NodeClient {
    NodeClient::new(
        logos_blockchain_zone_sdk::CommonHttpClient::new(config.auth.clone().map(Into::into)),
        config.addr.clone(),
    )
}
