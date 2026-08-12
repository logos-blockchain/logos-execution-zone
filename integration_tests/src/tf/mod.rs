//! Testing-framework deployments and Cucumber support for LEZ tests.

/// Independently deployable LEZ applications.
pub use apps::{
    BedrockApp, BedrockCluster, IndexerApp, LezIndexerClient, LezRuntime, LezSequencerClient,
    LezSequencerRegistryApp, LezSequencerRegistryClient, SequencerApp, WalletApp,
};
/// Complete-stack deployment helpers.
pub use stack::{LezLocalApp, LezStackHandle, shutdown_lez_deployment};
/// Indexer convergence polling helpers and errors.
pub use wait::{
    IndexerCatchUpError, wait_for_indexer_to_catch_up, wait_for_indexer_to_catch_up_with_timeout,
    wait_for_indexer_to_index_transactions_with_timeout, wait_for_indexer_to_reach_with_timeout,
};

mod apps;
mod stack;
/// Indexer convergence polling implementation.
pub mod wait;
