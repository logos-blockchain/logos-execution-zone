use crate::config::ClientConfig;

// The HTTP backend is the default and wins whenever both features are on, so
// `--all-features` builds (clippy, unit tests) never link the module backend,
// whose `lp_*` symbols only a module host provides. Build the module variant
// with `--no-default-features --features backend-module`.
#[cfg(not(any(feature = "backend-http", feature = "backend-module")))]
compile_error!("enable one of the features `backend-http` or `backend-module`");

#[cfg(all(feature = "backend-module", not(feature = "backend-http")))]
pub type NodeClient = logos_blockchain_zone_sdk_module_backend::NodeModuleClient;

#[cfg(all(feature = "backend-module", not(feature = "backend-http")))]
#[must_use]
pub fn node_client(config: &ClientConfig) -> NodeClient {
    NodeClient::bind(config.module_name())
}

#[cfg(feature = "backend-http")]
pub type NodeClient = logos_blockchain_zone_sdk::adapter::NodeHttpClient;

#[cfg(feature = "backend-http")]
#[must_use]
pub fn node_client(config: &ClientConfig) -> NodeClient {
    NodeClient::new(
        logos_blockchain_zone_sdk::CommonHttpClient::new(config.auth.clone().map(Into::into)),
        config.addr.clone(),
    )
}
