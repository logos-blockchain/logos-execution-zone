//! In-memory Storage nodes on one network, for other crates' tests.
//!
//! A node's CID is the canonical prefix and the SHA-256 of the bytes, which no real node computes;
//! within one network every node agrees on it, which is what tests rely on. A dataset's tree is
//! its one zero-padded block, so a zero-suffixed variant shares it, as on a real node.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
};

use async_trait::async_trait;
use common::storage_cid::{STORAGE_CID_PREFIX, StorageCid};
use sha2::{Digest as _, Sha256};

use crate::{BLOCK_SIZE, Error, Manifest, Storage};

/// The nodes that can fetch from one another.
#[derive(Clone, Default)]
pub struct MemoryNetwork(Arc<Mutex<Vec<Arc<Mutex<Node>>>>>);

#[derive(Default)]
struct Node {
    objects: HashMap<StorageCid, Vec<u8>>,
    advertised: HashSet<StorageCid>,
    online: bool,
}

/// One node of a [`MemoryNetwork`].
#[derive(Clone)]
pub struct MemoryStorage {
    network: MemoryNetwork,
    node: Arc<Mutex<Node>>,
}

impl MemoryNetwork {
    /// A new online node on this network.
    #[must_use]
    pub fn node(&self) -> MemoryStorage {
        let node = Arc::new(Mutex::new(Node {
            online: true,
            ..Node::default()
        }));
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&node));
        MemoryStorage {
            network: self.clone(),
            node,
        }
    }

    fn find(&self, cid: StorageCid) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find_map(|node| {
                let node = node.lock().unwrap_or_else(PoisonError::into_inner);
                (node.online && node.advertised.contains(&cid))
                    .then(|| node.objects.get(&cid).cloned())
                    .flatten()
            })
    }
}

impl MemoryStorage {
    /// Takes the node off the network, or puts it back; an offline node serves no peer.
    pub fn set_online(&self, online: bool) {
        self.lock().online = online;
    }

    /// Whether the node holds the dataset `cid` names.
    #[must_use]
    pub fn holds(&self, cid: StorageCid) -> bool {
        self.lock().objects.contains_key(&cid)
    }

    /// The CID any node gives `bytes`.
    #[must_use]
    pub fn cid_of(bytes: &[u8]) -> StorageCid {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        StorageCid::try_from([&STORAGE_CID_PREFIX[..], &digest].concat().as_slice())
            .expect("the canonical prefix and a digest form a CID")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Node> {
        self.node.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The dataset `cid` names, from the network unless `local`; kept only when `keep`, as a
    /// manifest fetch keeps no payload.
    fn object(&self, cid: StorageCid, local: bool, keep: bool) -> Result<Vec<u8>, Error> {
        if let Some(bytes) = self.lock().objects.get(&cid) {
            return Ok(bytes.clone());
        }
        let not_found = || Error::Status {
            status: reqwest::StatusCode::NOT_FOUND,
            body: format!("{cid} not found"),
        };
        if local {
            return Err(not_found());
        }
        let bytes = self.network.find(cid).ok_or_else(not_found)?;
        if keep {
            self.lock().objects.insert(cid, bytes.clone());
        }
        Ok(bytes)
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn upload(&self, bytes: Vec<u8>, advertise: bool) -> Result<StorageCid, Error> {
        let cid = Self::cid_of(&bytes);
        let mut node = self.lock();
        node.objects.insert(cid, bytes);
        if advertise {
            node.advertised.insert(cid);
        }
        Ok(cid)
    }

    async fn manifest(&self, cid: StorageCid) -> Result<Manifest, Error> {
        let bytes = self.object(cid, false, false)?;
        let block = bytes
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(&bytes[..0], |last| &bytes[..=last]);
        Ok(Manifest {
            tree_cid: hex::encode(Sha256::digest(block)),
            block_size: BLOCK_SIZE,
            dataset_size: u64::try_from(bytes.len()).expect("a dataset's length fits u64"),
            filename: None,
            mimetype: None,
            manifest_version: 0,
        })
    }

    async fn download(&self, cid: StorageCid, max_len: u64, local: bool) -> Result<Vec<u8>, Error> {
        let bytes = self.object(cid, local, true)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_len {
            return Err(Error::TooLong { max: max_len });
        }
        Ok(bytes)
    }

    async fn exists(&self, cid: StorageCid) -> Result<bool, Error> {
        Ok(self.holds(cid))
    }

    async fn delete(&self, cid: StorageCid) -> Result<(), Error> {
        let mut node = self.lock();
        node.objects.remove(&cid);
        node.advertised.remove(&cid);
        Ok(())
    }

    async fn set_advertise(&self, cid: StorageCid, advertise: bool) -> Result<(), Error> {
        let mut node = self.lock();
        if advertise {
            node.advertised.insert(cid);
        } else {
            node.advertised.remove(&cid);
        }
        Ok(())
    }

    async fn free_bytes(&self) -> Result<u64, Error> {
        Ok(u64::MAX)
    }
}
