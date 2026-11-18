//! The REST API of the Logos Storage node a LEZ service runs beside, holding each proof in one
//! canonical form: one dataset of at most one data block, with no filename and no MIME type.

use async_trait::async_trait;
use common::storage_cid::StorageCid;
use reqwest::StatusCode;
use serde::Deserialize;
use url::Url;

#[cfg(feature = "test-utils")]
pub mod memory;

/// The block size of the canonical form, 256 KiB; the proof cap fits one block.
pub const BLOCK_SIZE: u64 = 0x0004_0000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Storage node answered {status}: {body}")]
    Status { status: StatusCode, body: String },
    #[error("Storage node returned an unusable CID: {0}")]
    Cid(String),
    #[error("dataset exceeds the {max}-byte bound")]
    TooLong { max: u64 },
    #[error("manifest is not of the canonical form: {0}")]
    NonCanonical(&'static str),
    #[error("malformed Storage response: {0}")]
    Malformed(#[from] serde_json::Error),
}

impl Error {
    /// Whether the node does not hold, and could not find, what was asked for.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Status { status, .. } if *status == StatusCode::NOT_FOUND)
    }
}

/// What a manifest says of its dataset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub tree_cid: String,
    #[serde(deserialize_with = "number")]
    pub block_size: u64,
    #[serde(deserialize_with = "number")]
    pub dataset_size: u64,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub mimetype: Option<String>,
    #[serde(default)]
    pub manifest_version: u32,
}

impl Manifest {
    /// Refuses all but the form a canonical upload of at most `max_len` bytes gets.
    pub const fn check_canonical(&self, max_len: u64) -> Result<(), Error> {
        if self.manifest_version != 0 {
            return Err(Error::NonCanonical("manifest version"));
        }
        if self.block_size != BLOCK_SIZE {
            return Err(Error::NonCanonical("block size"));
        }
        if self.filename.is_some() {
            return Err(Error::NonCanonical("filename"));
        }
        if self.mimetype.is_some() {
            return Err(Error::NonCanonical("MIME type"));
        }
        if self.dataset_size > max_len {
            return Err(Error::TooLong { max: max_len });
        }
        Ok(())
    }
}

/// A Logos Storage node, as LEZ uses it.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Stores `bytes` in the canonical form and returns its CID. A dataset already stored keeps
    /// its blocks and has their expiry renewed.
    async fn upload(&self, bytes: Vec<u8>, advertise: bool) -> Result<StorageCid, Error>;

    /// The manifest `cid` names, from the network if it is not local, never advertised. The node
    /// keeps the manifest block it fetched.
    async fn manifest(&self, cid: StorageCid) -> Result<Manifest, Error>;

    /// The dataset `cid` names, refused past `max_len` bytes; from local blocks only with
    /// `local`, else fetched without advertising it.
    async fn download(&self, cid: StorageCid, max_len: u64, local: bool) -> Result<Vec<u8>, Error>;

    /// Whether the local store holds the manifest `cid` names.
    async fn exists(&self, cid: StorageCid) -> Result<bool, Error>;

    /// Drops the dataset `cid` names, with every block of its tree, from the local store.
    async fn delete(&self, cid: StorageCid) -> Result<(), Error>;

    /// Starts or stops announcing the local dataset `cid` names and serving it to peers.
    async fn set_advertise(&self, cid: StorageCid, advertise: bool) -> Result<(), Error>;

    /// The bytes the local store still takes.
    async fn free_bytes(&self) -> Result<u64, Error>;
}

/// The REST client of a node's API at `api`.
#[derive(Clone)]
pub struct StorageClient {
    http: reqwest::Client,
    api: Url,
}

impl StorageClient {
    #[must_use]
    pub fn new(api: Url) -> Self {
        Self {
            http: reqwest::Client::new(),
            api,
        }
    }

    fn url(&self, path: &str) -> Url {
        let mut url = self.api.clone();
        url.set_path(&format!("api/storage/v1/{path}"));
        url
    }

    fn data(&self, cid: StorageCid, suffix: &str) -> Url {
        self.url(&format!("data/{}{suffix}", text(cid)))
    }
}

#[async_trait]
impl Storage for StorageClient {
    async fn upload(&self, bytes: Vec<u8>, advertise: bool) -> Result<StorageCid, Error> {
        let mut url = self.url("data");
        url.query_pairs_mut()
            .append_pair("blockSize", &BLOCK_SIZE.to_string())
            .append_pair("advertise", &advertise.to_string());
        // No `Content-Type` and no `Content-Disposition`: either would name the dataset in its
        // manifest and so change its CID.
        let response = checked(self.http.post(url).body(bytes).send().await?).await?;
        parse(&response.text().await?)
    }

    async fn manifest(&self, cid: StorageCid) -> Result<Manifest, Error> {
        #[derive(Deserialize)]
        struct Content {
            manifest: Manifest,
        }
        let mut url = self.data(cid, "/network/manifest");
        url.query_pairs_mut().append_pair("advertise", "false");
        let response = checked(self.http.get(url).send().await?).await?;
        Ok(serde_json::from_slice::<Content>(&response.bytes().await?)?.manifest)
    }

    async fn download(&self, cid: StorageCid, max_len: u64, local: bool) -> Result<Vec<u8>, Error> {
        let url = if local {
            self.data(cid, "")
        } else {
            let mut url = self.data(cid, "/network/stream");
            url.query_pairs_mut().append_pair("advertise", "false");
            url
        };
        let mut response = checked(self.http.get(url).send().await?).await?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            let len = u64::try_from(bytes.len().saturating_add(chunk.len())).unwrap_or(u64::MAX);
            if len > max_len {
                return Err(Error::TooLong { max: max_len });
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn exists(&self, cid: StorageCid) -> Result<bool, Error> {
        let response = checked(self.http.get(self.data(cid, "/exists")).send().await?).await?;
        let answer: std::collections::HashMap<String, bool> =
            serde_json::from_slice(&response.bytes().await?)?;
        Ok(answer.into_values().next().unwrap_or(false))
    }

    async fn delete(&self, cid: StorageCid) -> Result<(), Error> {
        checked(self.http.delete(self.data(cid, "")).send().await?).await?;
        Ok(())
    }

    async fn set_advertise(&self, cid: StorageCid, advertise: bool) -> Result<(), Error> {
        let mut url = self.data(cid, "/advertise");
        url.query_pairs_mut()
            .append_pair("advertise", &advertise.to_string());
        checked(self.http.post(url).body("").send().await?).await?;
        Ok(())
    }

    async fn free_bytes(&self) -> Result<u64, Error> {
        #[derive(Deserialize)]
        struct Space {
            #[serde(rename = "quotaMaxBytes", deserialize_with = "number")]
            max: u64,
            #[serde(rename = "quotaUsedBytes", deserialize_with = "number")]
            used: u64,
            #[serde(rename = "quotaReservedBytes", deserialize_with = "number")]
            reserved: u64,
        }
        let response = checked(self.http.get(self.url("space")).send().await?).await?;
        let space: Space = serde_json::from_slice(&response.bytes().await?)?;
        Ok(space
            .max
            .saturating_sub(space.used)
            .saturating_sub(space.reserved))
    }
}

/// A CID in the base58btc multibase text form the node's paths take.
#[must_use]
pub fn text(cid: StorageCid) -> String {
    multibase::encode(multibase::Base::Base58Btc, cid.as_bytes())
}

/// A CID from any multibase text form.
pub fn parse(text: &str) -> Result<StorageCid, Error> {
    let text = text.trim();
    let (_, bytes) = multibase::decode(text).map_err(|_err| Error::Cid(text.to_owned()))?;
    StorageCid::try_from(bytes.as_slice()).map_err(|_err| Error::Cid(text.to_owned()))
}

async fn checked(response: reqwest::Response) -> Result<reqwest::Response, Error> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    Err(Error::Status { status, body })
}

/// A byte count the node writes as a JSON number or as a decimal string.
fn number<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Number(u64),
        Text(String),
    }
    match Number::deserialize(deserializer)? {
        Number::Number(number) => Ok(number),
        Number::Text(text) => text.parse().map_err(serde::de::Error::custom),
    }
}
