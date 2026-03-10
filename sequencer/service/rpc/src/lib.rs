use std::sync::Arc;

use common::{
    rpc_primitives::errors::{RpcError, RpcErrorKind},
    transaction::NSSATransaction,
};
use mempool::MemPoolHandle;
pub use net_utils::*;
#[cfg(feature = "standalone")]
use sequencer_core::mock::{MockBlockSettlementClient, MockIndexerClient};
use sequencer_core::{
    SequencerCore,
    block_settlement_client::{BlockSettlementClient, BlockSettlementClientTrait},
    indexer_client::{IndexerClient, IndexerClientTrait},
};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use self::types::err_rpc::RpcErr;

pub mod net_utils;
pub mod process;
pub mod types;

#[cfg(feature = "standalone")]
pub type JsonHandlerWithMockClients = JsonHandler<MockBlockSettlementClient, MockIndexerClient>;

// ToDo: Add necessary fields
pub struct JsonHandler<
    BC: BlockSettlementClientTrait = BlockSettlementClient,
    IC: IndexerClientTrait = IndexerClient,
> {
    sequencer_state: Arc<Mutex<SequencerCore<BC, IC>>>,
    mempool_handle: MemPoolHandle<NSSATransaction>,
    max_block_size: usize,
}

fn respond<T: Serialize>(val: T) -> Result<Value, RpcErr> {
    Ok(serde_json::to_value(val)?)
}

#[must_use]
pub fn rpc_error_responce_inverter(err: RpcError) -> RpcError {
    let content = err.error_struct.map(|error| match error {
        RpcErrorKind::HandlerError(val) | RpcErrorKind::InternalError(val) => val,
        RpcErrorKind::RequestValidationError(vall) => serde_json::to_value(vall).unwrap(),
    });
    RpcError {
        error_struct: None,
        code: err.code,
        message: err.message,
        data: content,
    }
}
