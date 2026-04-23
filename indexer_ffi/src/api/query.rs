use indexer_service_rpc::RpcClient;

use crate::{IndexerServiceFFI, api::PointerResult, errors::OperationStatus};

/// Stops and frees the resources associated with the given indexer service.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be stopped.
///
/// # Returns
///
/// An `OperationStatus` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
/// - The `IndexerServiceFFI` instance was created by this library
/// - The pointer will not be used after this function returns
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_last_block(
    indexer: *const IndexerServiceFFI,
) -> PointerResult<u64, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_last_finalized_block_id())
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            PointerResult::from_value,
        )
}
