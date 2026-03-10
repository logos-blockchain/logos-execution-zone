pub mod net_utils;
pub mod process;
pub mod types;

use std::sync::Arc;

use common::{
    rpc_primitives::errors::{RpcError, RpcErrorKind},
    transaction::NSSATransaction,
};
use mempool::MemPoolHandle;
pub use net_utils::*;
use sequencer_core::{
    SequencerCore,
    block_publisher::{BlockPublisherTrait, ZoneSdkPublisher},
    indexer_client::{IndexerClient, IndexerClientTrait},
};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use self::types::err_rpc::RpcErr;

// ToDo: Add necessary fields
pub struct JsonHandler<
    BP: BlockPublisherTrait = ZoneSdkPublisher,
    IC: IndexerClientTrait = IndexerClient,
> {
    sequencer_state: Arc<Mutex<SequencerCore<BP, IC>>>,
    mempool_handle: MemPoolHandle<NSSATransaction>,
    max_block_size: usize,
}

fn respond<T: Serialize>(val: T) -> Result<Value, RpcErr> {
    Ok(serde_json::to_value(val)?)
}

pub fn rpc_error_responce_inverter(err: RpcError) -> RpcError {
    let mut content: Option<Value> = None;
    if err.error_struct.is_some() {
        content = match err.error_struct.clone().unwrap() {
            RpcErrorKind::HandlerError(val) | RpcErrorKind::InternalError(val) => Some(val),
            RpcErrorKind::RequestValidationError(vall) => Some(serde_json::to_value(vall).unwrap()),
        };
    }
    RpcError {
        error_struct: None,
        code: err.code,
        message: err.message,
        data: content,
    }
}

#[cfg(feature = "standalone")]
use sequencer_core::mock::{MockBlockPublisher, MockIndexerClient};

#[cfg(feature = "standalone")]
pub type JsonHandlerWithMockClients = JsonHandler<MockBlockPublisher, MockIndexerClient>;
