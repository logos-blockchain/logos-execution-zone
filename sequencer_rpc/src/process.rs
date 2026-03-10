use std::collections::HashMap;

use actix_web::Error as HttpError;
use base64::{Engine, engine::general_purpose};
use common::{
    block::{AccountInitialData, HashableBlockData},
    rpc_primitives::{
        errors::RpcError,
        message::{Message, Request},
        parser::RpcRequest,
        requests::{
            GetAccountBalanceRequest, GetAccountBalanceResponse, GetAccountRequest,
            GetAccountResponse, GetAccountsNoncesRequest, GetAccountsNoncesResponse,
            GetBlockDataRequest, GetBlockDataResponse, GetBlockRangeDataRequest,
            GetBlockRangeDataResponse, GetGenesisIdRequest, GetGenesisIdResponse,
            GetInitialTestnetAccountsRequest, GetLastBlockRequest, GetLastBlockResponse,
            GetProgramIdsRequest, GetProgramIdsResponse, GetProofForCommitmentRequest,
            GetProofForCommitmentResponse, GetTransactionByHashRequest,
            GetTransactionByHashResponse, HelloRequest, HelloResponse, SendTxRequest,
            SendTxResponse,
        },
    },
    transaction::{NSSATransaction, TransactionMalformationError},
};
use itertools::Itertools as _;
use log::warn;
use nssa::{self, program::Program};
use sequencer_core::{
    block_settlement_client::BlockSettlementClientTrait, indexer_client::IndexerClientTrait,
};
use serde_json::Value;

use super::{JsonHandler, respond, types::err_rpc::RpcErr};

pub const HELLO: &str = "hello";
pub const SEND_TX: &str = "send_tx";
pub const GET_BLOCK: &str = "get_block";
pub const GET_BLOCK_RANGE: &str = "get_block_range";
pub const GET_GENESIS: &str = "get_genesis";
pub const GET_LAST_BLOCK: &str = "get_last_block";
pub const GET_ACCOUNT_BALANCE: &str = "get_account_balance";
pub const GET_TRANSACTION_BY_HASH: &str = "get_transaction_by_hash";
pub const GET_ACCOUNTS_NONCES: &str = "get_accounts_nonces";
pub const GET_ACCOUNT: &str = "get_account";
pub const GET_PROOF_FOR_COMMITMENT: &str = "get_proof_for_commitment";
pub const GET_PROGRAM_IDS: &str = "get_program_ids";

pub const HELLO_FROM_SEQUENCER: &str = "HELLO_FROM_SEQUENCER";

pub const TRANSACTION_SUBMITTED: &str = "Transaction submitted";

pub const GET_INITIAL_TESTNET_ACCOUNTS: &str = "get_initial_testnet_accounts";

pub trait Process: Send + Sync + 'static {
    fn process(&self, message: Message) -> impl Future<Output = Result<Message, HttpError>> + Send;
}

impl<
    BC: BlockSettlementClientTrait + Send + Sync + 'static,
    IC: IndexerClientTrait + Send + Sync + 'static,
> Process for JsonHandler<BC, IC>
{
    async fn process(&self, message: Message) -> Result<Message, HttpError> {
        let id = message.id();
        if let Message::Request(request) = message {
            let message_inner = self
                .process_request_internal(request)
                .await
                .map_err(|e| e.0);
            Ok(Message::response(id, message_inner))
        } else {
            Ok(Message::error(RpcError::parse_error(
                "JSON RPC Request format was expected".to_owned(),
            )))
        }
    }
}

impl<BC: BlockSettlementClientTrait, IC: IndexerClientTrait> JsonHandler<BC, IC> {
    /// Example of request processing
    #[allow(clippy::unused_async)]
    async fn process_temp_hello(&self, request: Request) -> Result<Value, RpcErr> {
        let _hello_request = HelloRequest::parse(Some(request.params))?;

        let response = HelloResponse {
            greeting: HELLO_FROM_SEQUENCER.to_string(),
        };

        respond(response)
    }

    async fn process_send_tx(&self, request: Request) -> Result<Value, RpcErr> {
        let send_tx_req = SendTxRequest::parse(Some(request.params))?;
        let tx = borsh::from_slice::<NSSATransaction>(&send_tx_req.transaction)
            .map_err(|e| {
                RpcErr(RpcError::invalid_params(format!(
                    "Failed to deserialize transaction: {e}"
                )))
            })?;
        let tx_hash = tx.hash();

        // Check transaction size against block size limit
        // Reserve ~200 bytes for block header overhead
        const BLOCK_HEADER_OVERHEAD: usize = 200;
        let tx_size = borsh::to_vec(&tx)
            .map_err(|_| TransactionMalformationError::FailedToDecode { tx: tx_hash })?
            .len();

        let max_tx_size = self.max_block_size.saturating_sub(BLOCK_HEADER_OVERHEAD);

        if tx_size > max_tx_size {
            return Err(TransactionMalformationError::TransactionTooLarge {
                size: tx_size,
                max: max_tx_size,
            }
            .into());
        }

        let authenticated_tx = tx
            .transaction_stateless_check()
            .inspect_err(|err| warn!("Error at pre_check {err:#?}"))?;

        // TODO: Do we need a timeout here? It will be usable if we have too many transactions to
        // process
        self.mempool_handle
            .push(authenticated_tx)
            .await
            .map_err(|_| {
                RpcErr(RpcError::new_internal_error(
                    None,
                    "Mempool is closed, cannot accept transactions",
                ))
            })?;

        let response = SendTxResponse {
            status: TRANSACTION_SUBMITTED.to_string(),
            tx_hash,
        };

        respond(response)
    }

    async fn process_get_block_data(&self, request: Request) -> Result<Value, RpcErr> {
        let get_block_req = GetBlockDataRequest::parse(Some(request.params))?;

        let block = {
            let state = self.sequencer_state.lock().await;

            state
                .block_store()
                .get_block_at_id(get_block_req.block_id)?
        };

        let response = GetBlockDataResponse {
            block: borsh::to_vec(&HashableBlockData::from(block)).unwrap(),
        };

        respond(response)
    }

    async fn process_get_block_range_data(&self, request: Request) -> Result<Value, RpcErr> {
        let get_block_req = GetBlockRangeDataRequest::parse(Some(request.params))?;

        let blocks = {
            let state = self.sequencer_state.lock().await;
            (get_block_req.start_block_id..=get_block_req.end_block_id)
                .map(|block_id| state.block_store().get_block_at_id(block_id))
                .map_ok(|block| {
                    borsh::to_vec(&HashableBlockData::from(block))
                        .expect("derived BorshSerialize should never fail")
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let response = GetBlockRangeDataResponse { blocks };

        respond(response)
    }

    async fn process_get_genesis(&self, request: Request) -> Result<Value, RpcErr> {
        let _get_genesis_req = GetGenesisIdRequest::parse(Some(request.params))?;

        let genesis_id = {
            let state = self.sequencer_state.lock().await;

            state.block_store().genesis_id()
        };

        let response = GetGenesisIdResponse { genesis_id };

        respond(response)
    }

    async fn process_get_last_block(&self, request: Request) -> Result<Value, RpcErr> {
        let _get_last_block_req = GetLastBlockRequest::parse(Some(request.params))?;

        let last_block = {
            let state = self.sequencer_state.lock().await;

            state.chain_height()
        };

        let response = GetLastBlockResponse { last_block };

        respond(response)
    }

    /// Returns the initial accounts for testnet
    /// ToDo: Useful only for testnet and needs to be removed later
    async fn get_initial_testnet_accounts(&self, request: Request) -> Result<Value, RpcErr> {
        let _get_initial_testnet_accounts_request =
            GetInitialTestnetAccountsRequest::parse(Some(request.params))?;

        let initial_accounts: Vec<AccountInitialData> = {
            let state = self.sequencer_state.lock().await;

            state.sequencer_config().initial_accounts.clone()
        };

        respond(initial_accounts)
    }

    /// Returns the balance of the account at the given account_id.
    /// The account_id must be a valid hex string of the correct length.
    async fn process_get_account_balance(&self, request: Request) -> Result<Value, RpcErr> {
        let get_account_req = GetAccountBalanceRequest::parse(Some(request.params))?;
        let account_id = get_account_req.account_id;

        let balance = {
            let state = self.sequencer_state.lock().await;
            let account = state.state().get_account_by_id(account_id);
            account.balance
        };

        let response = GetAccountBalanceResponse { balance };

        respond(response)
    }

    /// Returns the nonces of the accounts at the given account_ids.
    /// Each account_id must be a valid hex string of the correct length.
    async fn process_get_accounts_nonces(&self, request: Request) -> Result<Value, RpcErr> {
        let get_account_nonces_req = GetAccountsNoncesRequest::parse(Some(request.params))?;
        let account_ids = get_account_nonces_req.account_ids;

        let nonces = {
            let state = self.sequencer_state.lock().await;

            account_ids
                .into_iter()
                .map(|account_id| state.state().get_account_by_id(account_id).nonce)
                .collect()
        };

        let response = GetAccountsNoncesResponse { nonces };

        respond(response)
    }

    /// Returns account struct for given account_id.
    /// AccountId must be a valid hex string of the correct length.
    async fn process_get_account(&self, request: Request) -> Result<Value, RpcErr> {
        let get_account_nonces_req = GetAccountRequest::parse(Some(request.params))?;

        let account_id = get_account_nonces_req.account_id;

        let account = {
            let state = self.sequencer_state.lock().await;

            state.state().get_account_by_id(account_id)
        };

        let response = GetAccountResponse { account };

        respond(response)
    }

    /// Returns the transaction corresponding to the given hash, if it exists in the blockchain.
    /// The hash must be a valid hex string of the correct length.
    async fn process_get_transaction_by_hash(&self, request: Request) -> Result<Value, RpcErr> {
        let get_transaction_req = GetTransactionByHashRequest::parse(Some(request.params))?;
        let hash = get_transaction_req.hash;

        let transaction = {
            let state = self.sequencer_state.lock().await;
            state
                .block_store()
                .get_transaction_by_hash(hash)
                .map(|tx| borsh::to_vec(&tx).unwrap())
        };
        let base64_encoded = transaction.map(|tx| general_purpose::STANDARD.encode(tx));
        let response = GetTransactionByHashResponse {
            transaction: base64_encoded,
        };
        respond(response)
    }

    /// Returns the commitment proof, corresponding to commitment
    async fn process_get_proof_by_commitment(&self, request: Request) -> Result<Value, RpcErr> {
        let get_proof_req = GetProofForCommitmentRequest::parse(Some(request.params))?;

        let membership_proof = {
            let state = self.sequencer_state.lock().await;
            state
                .state()
                .get_proof_for_commitment(&get_proof_req.commitment)
        };
        let response = GetProofForCommitmentResponse { membership_proof };
        respond(response)
    }

    async fn process_get_program_ids(&self, request: Request) -> Result<Value, RpcErr> {
        let _get_proof_req = GetProgramIdsRequest::parse(Some(request.params))?;

        let mut program_ids = HashMap::new();
        program_ids.insert(
            "authenticated_transfer".to_string(),
            Program::authenticated_transfer_program().id(),
        );
        program_ids.insert("token".to_string(), Program::token().id());
        program_ids.insert("pinata".to_string(), Program::pinata().id());
        program_ids.insert("amm".to_string(), Program::amm().id());
        program_ids.insert(
            "privacy_preserving_circuit".to_string(),
            nssa::PRIVACY_PRESERVING_CIRCUIT_ID,
        );
        let response = GetProgramIdsResponse { program_ids };
        respond(response)
    }

    pub async fn process_request_internal(&self, request: Request) -> Result<Value, RpcErr> {
        match request.method.as_ref() {
            HELLO => self.process_temp_hello(request).await,
            SEND_TX => self.process_send_tx(request).await,
            GET_BLOCK => self.process_get_block_data(request).await,
            GET_BLOCK_RANGE => self.process_get_block_range_data(request).await,
            GET_GENESIS => self.process_get_genesis(request).await,
            GET_LAST_BLOCK => self.process_get_last_block(request).await,
            GET_INITIAL_TESTNET_ACCOUNTS => self.get_initial_testnet_accounts(request).await,
            GET_ACCOUNT_BALANCE => self.process_get_account_balance(request).await,
            GET_ACCOUNTS_NONCES => self.process_get_accounts_nonces(request).await,
            GET_ACCOUNT => self.process_get_account(request).await,
            GET_TRANSACTION_BY_HASH => self.process_get_transaction_by_hash(request).await,
            GET_PROOF_FOR_COMMITMENT => self.process_get_proof_by_commitment(request).await,
            GET_PROGRAM_IDS => self.process_get_program_ids(request).await,
            _ => Err(RpcErr(RpcError::method_not_found(request.method))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr as _, sync::Arc, time::Duration};

    use base58::ToBase58;
    use base64::{Engine, engine::general_purpose};
    use bedrock_client::BackoffConfig;
    use common::{
        block::AccountInitialData, config::BasicAuth, test_utils::sequencer_sign_key_for_testing,
        transaction::NSSATransaction,
    };
    use nssa::AccountId;
    use sequencer_core::{
        config::{BedrockConfig, SequencerConfig},
        mock::{MockBlockSettlementClient, MockIndexerClient, SequencerCoreWithMockClients},
    };
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    use crate::rpc_handler;

    type JsonHandlerWithMockClients =
        crate::JsonHandler<MockBlockSettlementClient, MockIndexerClient>;

    fn sequencer_config_for_tests() -> SequencerConfig {
        let tempdir = tempdir().unwrap();
        let home = tempdir.path().to_path_buf();
        let acc1_id: Vec<u8> = vec![
            148, 179, 206, 253, 199, 51, 82, 86, 232, 2, 152, 122, 80, 243, 54, 207, 237, 112, 83,
            153, 44, 59, 204, 49, 128, 84, 160, 227, 216, 149, 97, 102,
        ];

        let acc2_id: Vec<u8> = vec![
            30, 145, 107, 3, 207, 73, 192, 230, 160, 63, 238, 207, 18, 69, 54, 216, 103, 244, 92,
            94, 124, 248, 42, 16, 141, 19, 119, 18, 14, 226, 140, 204,
        ];

        let initial_acc1 = AccountInitialData {
            account_id: AccountId::from_str(&acc1_id.to_base58()).unwrap(),
            balance: 10000,
        };

        let initial_acc2 = AccountInitialData {
            account_id: AccountId::from_str(&acc2_id.to_base58()).unwrap(),
            balance: 20000,
        };

        let initial_accounts = vec![initial_acc1, initial_acc2];

        SequencerConfig {
            home,
            override_rust_log: Some("info".to_string()),
            genesis_id: 1,
            is_genesis_random: false,
            max_num_tx_in_block: 10,
            max_block_size: bytesize::ByteSize::mib(1),
            mempool_max_size: 1000,
            block_create_timeout: Duration::from_secs(1),
            port: 8080,
            initial_accounts,
            initial_commitments: vec![],
            signing_key: *sequencer_sign_key_for_testing().value(),
            retry_pending_blocks_timeout: Duration::from_secs(60 * 4),
            bedrock_config: BedrockConfig {
                backoff: BackoffConfig {
                    start_delay: Duration::from_millis(100),
                    max_retries: 5,
                },
                channel_id: [42; 32].into(),
                node_url: "http://localhost:8080".parse().unwrap(),
                auth: Some(BasicAuth {
                    username: "user".to_string(),
                    password: None,
                }),
            },
            indexer_rpc_url: "ws://localhost:8779".parse().unwrap(),
        }
    }

    async fn components_for_tests() -> (
        JsonHandlerWithMockClients,
        Vec<AccountInitialData>,
        NSSATransaction,
    ) {
        let config = sequencer_config_for_tests();

        let (mut sequencer_core, mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config).await;
        let initial_accounts = sequencer_core.sequencer_config().initial_accounts.clone();

        let signing_key = nssa::PrivateKey::try_new([1; 32]).unwrap();
        let balance_to_move = 10;
        let tx = common::test_utils::create_transaction_native_token_transfer(
            AccountId::from_str(
                &[
                    148, 179, 206, 253, 199, 51, 82, 86, 232, 2, 152, 122, 80, 243, 54, 207, 237,
                    112, 83, 153, 44, 59, 204, 49, 128, 84, 160, 227, 216, 149, 97, 102,
                ]
                .to_base58(),
            )
            .unwrap(),
            0,
            AccountId::from_str(&[2; 32].to_base58()).unwrap(),
            balance_to_move,
            signing_key,
        );

        mempool_handle
            .push(tx.clone())
            .await
            .expect("Mempool is closed, this is a bug");

        sequencer_core
            .produce_new_block_with_mempool_transactions()
            .unwrap();

        let max_block_size = sequencer_core.sequencer_config().max_block_size.as_u64() as usize;
        let sequencer_core = Arc::new(Mutex::new(sequencer_core));

        (
            JsonHandlerWithMockClients {
                sequencer_state: sequencer_core,
                mempool_handle,
                max_block_size,
            },
            initial_accounts,
            tx,
        )
    }

    async fn call_rpc_handler_with_json(
        handler: JsonHandlerWithMockClients,
        request_json: Value,
    ) -> Value {
        use actix_web::{App, test, web};

        let app = test::init_service(App::new().app_data(web::Data::new(handler)).route(
            "/",
            web::post().to(rpc_handler::<JsonHandlerWithMockClients>),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .set_json(request_json)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;

        serde_json::from_slice(&body).unwrap()
    }

    #[actix_web::test]
    async fn test_get_account_balance_for_non_existent_account() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_account_balance",
            "params": { "account_id": "11".repeat(16) },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "balance": 0
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_account_balance_for_invalid_base58() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_account_balance",
            "params": { "account_id": "not_a_valid_base58" },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "cause": {
                    "info": {
                        "error_message": "Failed parsing args: invalid base58: InvalidBase58Character('_', 3)"
                    },
                    "name": "PARSE_ERROR"
                },
                "code": -32700,
                "data": "Failed parsing args: invalid base58: InvalidBase58Character('_', 3)",
                "message": "Parse error",
                "name": "REQUEST_VALIDATION_ERROR"
            },
        });
        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_account_balance_for_invalid_length() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_account_balance",
            "params": { "account_id": "cafecafe" },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "cause": {
                    "info": {
                        "error_message": "Failed parsing args: invalid length: expected 32 bytes, got 6"
                    },
                    "name": "PARSE_ERROR"
                },
                "code": -32700,
                "data": "Failed parsing args: invalid length: expected 32 bytes, got 6",
                "message": "Parse error",
                "name": "REQUEST_VALIDATION_ERROR"
            },
        });
        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_account_balance_for_existing_account() {
        let (json_handler, initial_accounts, _) = components_for_tests().await;

        let acc1_id = initial_accounts[0].account_id;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_account_balance",
            "params": { "account_id": acc1_id },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "balance": 10000 - 10
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_accounts_nonces_for_non_existent_account() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_accounts_nonces",
            "params": { "account_ids": ["11".repeat(16)] },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "nonces": [ 0 ]
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_accounts_nonces_for_existent_account() {
        let (json_handler, initial_accounts, _) = components_for_tests().await;

        let acc1_id = initial_accounts[0].account_id;
        let acc2_id = initial_accounts[1].account_id;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_accounts_nonces",
            "params": { "account_ids": [acc1_id, acc2_id] },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "nonces": [ 1, 0 ]
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_account_data_for_non_existent_account() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_account",
            "params": { "account_id": "11".repeat(16) },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "account": {
                    "balance": 0,
                    "nonce": 0,
                    "program_owner": [ 0, 0, 0, 0, 0, 0, 0, 0],
                    "data": [],
                }
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_transaction_by_hash_for_non_existent_hash() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_transaction_by_hash",
            "params": { "hash": "cafe".repeat(16) },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "transaction": null
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_transaction_by_hash_for_invalid_hex() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_transaction_by_hash",
            "params": { "hash": "not_a_valid_hex" },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "cause": {
                    "info": {
                        "error_message": "Failed parsing args: Odd number of digits"
                    },
                    "name": "PARSE_ERROR"
                },
                "code": -32700,
                "data": "Failed parsing args: Odd number of digits",
                "message": "Parse error",
                "name": "REQUEST_VALIDATION_ERROR"
            },
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_transaction_by_hash_for_invalid_length() {
        let (json_handler, _, _) = components_for_tests().await;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_transaction_by_hash",
            "params": { "hash": "cafecafe" },
            "id": 1
        });
        let expected_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "cause": {
                    "info": {
                        "error_message": "Failed parsing args: Invalid string length"
                    },
                    "name": "PARSE_ERROR"
                },
                "code": -32700,
                "data": "Failed parsing args: Invalid string length",
                "message": "Parse error",
                "name": "REQUEST_VALIDATION_ERROR"
            }
        });

        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }

    #[actix_web::test]
    async fn test_get_transaction_by_hash_for_existing_transaction() {
        let (json_handler, _, tx) = components_for_tests().await;
        let tx_hash_hex = hex::encode(tx.hash());
        let expected_base64_encoded = general_purpose::STANDARD.encode(borsh::to_vec(&tx).unwrap());

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_transaction_by_hash",
            "params": { "hash": tx_hash_hex},
            "id": 1
        });

        let expected_response = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "transaction": expected_base64_encoded,
            }
        });
        let response = call_rpc_handler_with_json(json_handler, request).await;

        assert_eq!(response, expected_response);
    }
}
