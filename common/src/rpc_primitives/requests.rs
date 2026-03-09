use std::collections::HashMap;

use nssa::AccountId;
use nssa_core::program::ProgramId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    errors::RpcParseError,
    parser::{RpcRequest, parse_params},
};
use crate::{HashType, parse_request};

mod base64_deser {
    use base64::{Engine as _, engine::general_purpose};
    use serde::{self, Deserialize, Deserializer, Serializer, ser::SerializeSeq as _};

    pub mod vec {
        use super::*;

        pub fn serialize<S>(bytes_vec: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(bytes_vec.len()))?;
            for bytes in bytes_vec {
                let s = general_purpose::STANDARD.encode(bytes);
                seq.serialize_element(&s)?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let base64_strings: Vec<String> = Deserialize::deserialize(deserializer)?;
            base64_strings
                .into_iter()
                .map(|s| {
                    general_purpose::STANDARD
                        .decode(&s)
                        .map_err(serde::de::Error::custom)
                })
                .collect()
        }
    }

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64_string = general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&base64_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base64_string: String = Deserialize::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(&base64_string)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HelloRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterAccountRequest {
    pub account_id: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SendTxRequest {
    #[serde(with = "base64_deser")]
    pub transaction: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockDataRequest {
    pub block_id: u64,
}

/// Get a range of blocks from `start_block_id` to `end_block_id` (inclusive).
#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockRangeDataRequest {
    pub start_block_id: u64,
    pub end_block_id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetGenesisIdRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetLastBlockRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetInitialTestnetAccountsRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAccountBalanceRequest {
    pub account_id: AccountId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetTransactionByHashRequest {
    pub hash: HashType,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAccountsNoncesRequest {
    pub account_ids: Vec<AccountId>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAccountRequest {
    pub account_id: AccountId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetProofForCommitmentRequest {
    pub commitment: nssa_core::Commitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetProgramIdsRequest;

parse_request!(HelloRequest);
parse_request!(RegisterAccountRequest);
parse_request!(SendTxRequest);
parse_request!(GetBlockDataRequest);
parse_request!(GetBlockRangeDataRequest);
parse_request!(GetGenesisIdRequest);
parse_request!(GetLastBlockRequest);
parse_request!(GetInitialTestnetAccountsRequest);
parse_request!(GetAccountBalanceRequest);
parse_request!(GetTransactionByHashRequest);
parse_request!(GetAccountsNoncesRequest);
parse_request!(GetProofForCommitmentRequest);
parse_request!(GetAccountRequest);
parse_request!(GetProgramIdsRequest);

#[derive(Serialize, Deserialize, Debug)]
pub struct HelloResponse {
    pub greeting: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterAccountResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SendTxResponse {
    pub status: String,
    pub tx_hash: HashType,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockDataResponse {
    #[serde(with = "base64_deser")]
    pub block: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockRangeDataResponse {
    #[serde(with = "base64_deser::vec")]
    pub blocks: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetGenesisIdResponse {
    pub genesis_id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetLastBlockResponse {
    pub last_block: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAccountBalanceResponse {
    pub balance: u128,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAccountsNoncesResponse {
    pub nonces: Vec<u128>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetTransactionByHashResponse {
    pub transaction: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAccountResponse {
    pub account: nssa::Account,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetProofForCommitmentResponse {
    pub membership_proof: Option<nssa_core::MembershipProof>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetProgramIdsResponse {
    pub program_ids: HashMap<String, ProgramId>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetInitialTestnetAccountsResponse {
    /// Hex encoded account id.
    pub account_id: String,
    pub balance: u64,
}
