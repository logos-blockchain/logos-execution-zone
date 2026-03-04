use indexer_service_protocol::{Account, AccountId, Block, BlockId, HashType, Transaction};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// Search results structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResults {
    pub blocks: Vec<Block>,
    pub transactions: Vec<Transaction>,
    pub accounts: Vec<(AccountId, Account)>,
}

/// RPC client type
#[cfg(feature = "ssr")]
pub type IndexerRpcClient = jsonrpsee::http_client::HttpClient;

/// Get account information by ID
#[server]
pub async fn get_account(account_id: AccountId) -> Result<Account, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_account(account_id)
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Search for a block, transaction, or account by query string
#[server]
pub async fn search(query: String) -> Result<SearchResults, ServerFnError> {
    use std::str::FromStr as _;

    use indexer_service_rpc::RpcClient as _;

    let client = expect_context::<IndexerRpcClient>();

    let mut blocks = Vec::new();
    let mut transactions = Vec::new();
    let mut accounts = Vec::new();

    // Try as hash
    if let Ok(hash) = HashType::from_str(&query) {
        // Try as block hash
        if let Ok(block) = client.get_block_by_hash(hash).await {
            blocks.push(block);
        }

        // Try as transaction hash
        if let Ok(tx) = client.get_transaction(hash).await {
            transactions.push(tx);
        }
    }

    // Try as account ID
    if let Ok(account_id) = AccountId::from_str(&query)
        && let Ok(account) = client.get_account(account_id).await
    {
        accounts.push((account_id, account));
    }

    // Try as block ID
    if let Ok(block_id) = query.parse::<u64>()
        && let Ok(block) = client.get_block_by_id(block_id).await
    {
        blocks.push(block);
    }

    Ok(SearchResults {
        blocks,
        transactions,
        accounts,
    })
}

/// Get block by ID
#[server]
pub async fn get_block_by_id(block_id: BlockId) -> Result<Block, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_block_by_id(block_id)
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Get latest block ID
#[server]
pub async fn get_latest_block_id() -> Result<BlockId, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_last_finalized_block_id()
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Get block by hash
#[server]
pub async fn get_block_by_hash(block_hash: HashType) -> Result<Block, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_block_by_hash(block_hash)
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Get transaction by hash
#[server]
pub async fn get_transaction(tx_hash: HashType) -> Result<Transaction, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_transaction(tx_hash)
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Get blocks with pagination
#[server]
pub async fn get_blocks(before: Option<u64>, limit: u32) -> Result<Vec<Block>, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_blocks(before, limit)
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Get transactions by account
#[server]
pub async fn get_transactions_by_account(
    account_id: AccountId,
    limit: u32,
    offset: u32,
) -> Result<Vec<Transaction>, ServerFnError> {
    use indexer_service_rpc::RpcClient as _;
    let client = expect_context::<IndexerRpcClient>();
    client
        .get_transactions_by_account(account_id, limit, offset)
        .await
        .map_err(|e| ServerFnError::ServerError(format!("RPC error: {}", e)))
}

/// Create the RPC client for the indexer service (server-side only)
#[cfg(feature = "ssr")]
pub fn create_indexer_rpc_client(url: &url::Url) -> Result<IndexerRpcClient, String> {
    use jsonrpsee::http_client::HttpClientBuilder;
    use log::info;

    info!("Connecting to Indexer RPC on URL: {url}");

    HttpClientBuilder::default()
        .build(url.as_str())
        .map_err(|e| format!("Failed to create RPC client: {e}"))
}
