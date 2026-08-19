#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to setup RPC server")]
    RpcServerSetupFailed(#[source] std::io::Error),

    #[error("Failed to retrieve local address")]
    LocalAddrRetrievingFailed(#[source] std::io::Error),

    #[error("RPC server has stopped unexpectedly")]
    RpcServerStoppedUnexpectedly,

    #[error("RPC server has already been stopped")]
    RpcServerAlreadyStopped(#[from] jsonrpsee::server::AlreadyStoppedError),
}
