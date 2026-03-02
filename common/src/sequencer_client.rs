use std::{collections::HashMap, ops::RangeInclusive};

use anyhow::Result;
use nssa::AccountId;
use nssa_core::program::ProgramId;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::rpc_primitives::requests::{
    GetAccountBalanceRequest, GetAccountBalanceResponse, GetBlockDataRequest, GetBlockDataResponse,
    GetGenesisIdRequest, GetGenesisIdResponse, GetInitialTestnetAccountsRequest,
};
use crate::{
    HashType,
    config::BasicAuth,
    error::{SequencerClientError, SequencerRpcError},
    rpc_primitives::{
        self,
        requests::{
            GetAccountRequest, GetAccountResponse, GetAccountsNoncesRequest,
            GetAccountsNoncesResponse, GetBlockRangeDataRequest, GetBlockRangeDataResponse,
            GetInitialTestnetAccountsResponse, GetLastBlockRequest, GetLastBlockResponse,
            GetProgramIdsRequest, GetProgramIdsResponse, GetProofForCommitmentRequest,
            GetProofForCommitmentResponse, GetTransactionByHashRequest,
            GetTransactionByHashResponse, SendTxRequest, SendTxResponse,
        },
    },
    transaction::NSSATransaction,
};

#[derive(Clone)]
pub struct SequencerClient {
    pub client: reqwest::Client,
    pub sequencer_addr: Url,
    pub basic_auth: Option<BasicAuth>,
}

impl SequencerClient {
    pub fn new(sequencer_addr: Url) -> Result<Self> {
        Self::new_with_auth(sequencer_addr, None)
    }

    pub fn new_with_auth(sequencer_addr: Url, basic_auth: Option<BasicAuth>) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                // Add more fields if needed
                .timeout(std::time::Duration::from_secs(60))
                // Should be kept in sync with server keep-alive settings
                .pool_idle_timeout(std::time::Duration::from_secs(5))
                .build()?,
            sequencer_addr,
            basic_auth,
        })
    }

    pub async fn call_method_with_payload(
        &self,
        method: &str,
        payload: Value,
    ) -> Result<Value, SequencerClientError> {
        let request =
            rpc_primitives::message::Request::from_payload_version_2_0(method.to_string(), payload);

        log::debug!(
            "Calling method {method} with payload {request:?} to sequencer at {}",
            self.sequencer_addr
        );

        let strategy = tokio_retry::strategy::FixedInterval::from_millis(10000).take(60);

        let response_vall = tokio_retry::Retry::spawn(strategy, || async {
            let mut call_builder = self.client.post(self.sequencer_addr.clone());

            if let Some(BasicAuth { username, password }) = &self.basic_auth {
                call_builder = call_builder.basic_auth(username, password.as_deref());
            }

            let call_res_res = call_builder.json(&request).send().await;

            match call_res_res {
                Err(err) => Err(err),
                Ok(call_res) => call_res.json::<Value>().await,
            }
        })
        .await?;

        #[derive(Debug, Clone, Deserialize)]
        #[allow(dead_code)]
        pub struct SequencerRpcResponse {
            pub jsonrpc: String,
            pub result: serde_json::Value,
            pub id: u64,
        }

        if let Ok(response) = serde_json::from_value::<SequencerRpcResponse>(response_vall.clone())
        {
            Ok(response.result)
        } else {
            let err_resp = serde_json::from_value::<SequencerRpcError>(response_vall)?;

            Err(err_resp.into())
        }
    }

    /// Get block data at `block_id` from sequencer
    pub async fn get_block(
        &self,
        block_id: u64,
    ) -> Result<GetBlockDataResponse, SequencerClientError> {
        let block_req = GetBlockDataRequest { block_id };

        let req = serde_json::to_value(block_req)?;

        let resp = self.call_method_with_payload("get_block", req).await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    pub async fn get_block_range(
        &self,
        range: RangeInclusive<u64>,
    ) -> Result<GetBlockRangeDataResponse, SequencerClientError> {
        let block_req = GetBlockRangeDataRequest {
            start_block_id: *range.start(),
            end_block_id: *range.end(),
        };

        let req = serde_json::to_value(block_req)?;

        let resp = self
            .call_method_with_payload("get_block_range", req)
            .await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Get last known `blokc_id` from sequencer
    pub async fn get_last_block(&self) -> Result<GetLastBlockResponse, SequencerClientError> {
        let block_req = GetLastBlockRequest {};

        let req = serde_json::to_value(block_req)?;

        let resp = self.call_method_with_payload("get_last_block", req).await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Get account public balance for `account_id`. `account_id` must be a valid hex-string for 32
    /// bytes.
    pub async fn get_account_balance(
        &self,
        account_id: AccountId,
    ) -> Result<GetAccountBalanceResponse, SequencerClientError> {
        let block_req = GetAccountBalanceRequest { account_id };

        let req = serde_json::to_value(block_req)?;

        let resp = self
            .call_method_with_payload("get_account_balance", req)
            .await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Get accounts nonces for `account_ids`. `account_ids` must be a list of valid hex-strings for
    /// 32 bytes.
    pub async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<GetAccountsNoncesResponse, SequencerClientError> {
        let block_req = GetAccountsNoncesRequest { account_ids };

        let req = serde_json::to_value(block_req)?;

        let resp = self
            .call_method_with_payload("get_accounts_nonces", req)
            .await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    pub async fn get_account(
        &self,
        account_id: AccountId,
    ) -> Result<GetAccountResponse, SequencerClientError> {
        let block_req = GetAccountRequest { account_id };

        let req = serde_json::to_value(block_req)?;

        let resp = self.call_method_with_payload("get_account", req).await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Get transaction details for `hash`.
    pub async fn get_transaction_by_hash(
        &self,
        hash: HashType,
    ) -> Result<GetTransactionByHashResponse, SequencerClientError> {
        let block_req = GetTransactionByHashRequest { hash };

        let req = serde_json::to_value(block_req)?;

        let resp = self
            .call_method_with_payload("get_transaction_by_hash", req)
            .await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Send transaction to sequencer
    pub async fn send_tx_public(
        &self,
        transaction: nssa::PublicTransaction,
    ) -> Result<SendTxResponse, SequencerClientError> {
        let transaction = NSSATransaction::Public(transaction);

        let tx_req = SendTxRequest {
            transaction: borsh::to_vec(&transaction).unwrap(),
        };

        let req = serde_json::to_value(tx_req)?;

        let resp = self.call_method_with_payload("send_tx", req).await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Send transaction to sequencer
    pub async fn send_tx_private(
        &self,
        transaction: nssa::PrivacyPreservingTransaction,
    ) -> Result<SendTxResponse, SequencerClientError> {
        let transaction = NSSATransaction::PrivacyPreserving(transaction);

        let tx_req = SendTxRequest {
            transaction: borsh::to_vec(&transaction).unwrap(),
        };

        let req = serde_json::to_value(tx_req)?;

        let resp = self.call_method_with_payload("send_tx", req).await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Get genesis id from sequencer
    pub async fn get_genesis_id(&self) -> Result<GetGenesisIdResponse, SequencerClientError> {
        let genesis_req = GetGenesisIdRequest {};

        let req = serde_json::to_value(genesis_req).unwrap();

        let resp = self
            .call_method_with_payload("get_genesis", req)
            .await
            .unwrap();

        let resp_deser = serde_json::from_value(resp).unwrap();

        Ok(resp_deser)
    }

    /// Get initial testnet accounts from sequencer
    pub async fn get_initial_testnet_accounts(
        &self,
    ) -> Result<Vec<GetInitialTestnetAccountsResponse>, SequencerClientError> {
        let acc_req = GetInitialTestnetAccountsRequest {};

        let req = serde_json::to_value(acc_req).unwrap();

        let resp = self
            .call_method_with_payload("get_initial_testnet_accounts", req)
            .await
            .unwrap();

        let resp_deser = serde_json::from_value(resp).unwrap();

        Ok(resp_deser)
    }

    /// Get proof for commitment
    pub async fn get_proof_for_commitment(
        &self,
        commitment: nssa_core::Commitment,
    ) -> Result<Option<nssa_core::MembershipProof>, SequencerClientError> {
        let acc_req = GetProofForCommitmentRequest { commitment };

        let req = serde_json::to_value(acc_req).unwrap();

        let resp = self
            .call_method_with_payload("get_proof_for_commitment", req)
            .await
            .unwrap();

        let resp_deser = serde_json::from_value::<GetProofForCommitmentResponse>(resp)
            .unwrap()
            .membership_proof;

        Ok(resp_deser)
    }

    pub async fn send_tx_program(
        &self,
        transaction: nssa::ProgramDeploymentTransaction,
    ) -> Result<SendTxResponse, SequencerClientError> {
        let transaction = NSSATransaction::ProgramDeployment(transaction);

        let tx_req = SendTxRequest {
            transaction: borsh::to_vec(&transaction).unwrap(),
        };

        let req = serde_json::to_value(tx_req)?;

        let resp = self.call_method_with_payload("send_tx", req).await?;

        let resp_deser = serde_json::from_value(resp)?;

        Ok(resp_deser)
    }

    /// Get Ids of the programs used by the node
    pub async fn get_program_ids(
        &self,
    ) -> Result<HashMap<String, ProgramId>, SequencerClientError> {
        let acc_req = GetProgramIdsRequest {};

        let req = serde_json::to_value(acc_req).unwrap();

        let resp = self
            .call_method_with_payload("get_program_ids", req)
            .await
            .unwrap();

        let resp_deser = serde_json::from_value::<GetProgramIdsResponse>(resp)
            .unwrap()
            .program_ids;

        Ok(resp_deser)
    }
}
