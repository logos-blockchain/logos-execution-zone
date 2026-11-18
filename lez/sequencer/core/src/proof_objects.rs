//! The proofs this node holds in Logos Storage, by LEZ digest.
//!
//! An object is held while the proof store has its proof, pinned by a chain entry or cached, or
//! while a hold names it: a mempool entry, an approval promise or a download in flight. Once
//! released it is served for the serving window more, then deleted. Every CID the map keeps is
//! the one this node's own canonical upload of verified bytes returned, so no peer's hint enters
//! it.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use chain_state::ProofStore;
use common::storage_cid::StorageCid;
use kameo::actor::ActorRef;
use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};
use logos_storage::Storage;
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{DeleteProofObject, GetProofObjects, PutProofObject},
};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] logos_storage::Error),
    #[error("Failed to persist a proof object: {0:#}")]
    Record(anyhow::Error),
}

/// Where the map outlives a restart.
#[async_trait]
pub trait ObjectRecords: Send + Sync {
    async fn load(&self) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn put(&self, digest: ProofDigest, bytes: Vec<u8>) -> anyhow::Result<()>;
    async fn delete(&self, digest: ProofDigest) -> anyhow::Result<()>;
}

/// The node's Logos Storage objects.
pub struct ProofObjects {
    storage: Arc<dyn Storage>,
    proofs: ProofStore,
    records: Arc<dyn ObjectRecords>,
    serving_window: Duration,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<ProofDigest, Object>,
    holds: BTreeMap<ProofDigest, usize>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct Object {
    digest: ProofDigest,
    cid: StorageCid,
    /// The manifest's tree, which another dataset can share: deleting either drops the other's
    /// blocks.
    tree: String,
    /// Seconds since the epoch when the last holder let go, if one did.
    released_at: Option<u64>,
}

impl ProofObjects {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        proofs: ProofStore,
        records: Arc<dyn ObjectRecords>,
        serving_window: Duration,
    ) -> Self {
        Self {
            storage,
            proofs,
            records,
            serving_window,
            state: Mutex::new(State::default()),
        }
    }

    /// Installs the map persisted before a restart, without the objects the node no longer
    /// holds.
    pub async fn restore(&self) -> Result<(), Error> {
        for bytes in self.records.load().await.map_err(Error::Record)? {
            let Ok(object) = Object::try_from_slice(&bytes) else {
                warn!("Skipping a persisted proof object that doesn't decode");
                continue;
            };
            if self.storage.exists(object.cid).await? {
                self.lock().objects.insert(object.digest, object);
            } else {
                self.records
                    .delete(object.digest)
                    .await
                    .map_err(Error::Record)?;
            }
        }
        Ok(())
    }

    /// The CID of the proof `digest` names, if this node holds it.
    #[must_use]
    pub fn locator(&self, digest: &ProofDigest) -> Option<StorageCid> {
        self.lock().objects.get(digest).map(|object| object.cid)
    }

    /// Stores `proof` in the canonical form, served to peers, and returns its CID. The proof
    /// enters the proof store, which holds the object.
    pub async fn seed(&self, proof: &Proof) -> Result<StorageCid, Error> {
        self.store(proof, true).await
    }

    /// Keeps the object of `digest` until as many [`Self::release`]s.
    pub fn hold(&self, digest: ProofDigest) {
        let mut state = self.lock();
        let holds = state.holds.entry(digest).or_default();
        *holds = holds.saturating_add(1);
    }

    pub fn release(&self, digest: &ProofDigest) {
        let mut state = self.lock();
        if let Some(holds) = state.holds.get_mut(digest) {
            *holds = holds.saturating_sub(1);
            if *holds == 0 {
                state.holds.remove(digest);
            }
        }
    }

    /// Marks the objects held or released at `now` seconds since the epoch, and deletes the
    /// ones whose serving window has closed.
    pub async fn sweep(&self, now: u64) -> Result<(), Error> {
        let window = self.serving_window.as_secs();
        let (changed, expired) = {
            let mut state = self.lock();
            let State { objects, holds } = &mut *state;
            let mut changed = Vec::new();
            for object in objects.values_mut() {
                let held =
                    holds.contains_key(&object.digest) || self.proofs.contains(&object.digest);
                let released_at = (!held).then(|| object.released_at.unwrap_or(now));
                if released_at != object.released_at {
                    object.released_at = released_at;
                    changed.push(object.clone());
                }
            }
            let expired: Vec<Object> = objects
                .values()
                .filter(|object| {
                    object
                        .released_at
                        .is_some_and(|at| now.saturating_sub(at) >= window)
                })
                .cloned()
                .collect();
            for object in &expired {
                objects.remove(&object.digest);
            }
            (changed, expired)
        };
        for object in changed {
            self.persist(&object).await?;
        }
        for object in expired {
            self.records
                .delete(object.digest)
                .await
                .map_err(Error::Record)?;
            // A tree a remaining object shares stays, to expire with the node's TTL.
            let shared = self
                .lock()
                .objects
                .values()
                .any(|kept| kept.tree == object.tree);
            if !shared && let Err(err) = self.storage.delete(object.cid).await {
                warn!(cid = %object.cid, error = %err, "Failed to delete a released proof object");
            }
        }
        Ok(())
    }

    async fn store(&self, proof: &Proof, advertise: bool) -> Result<StorageCid, Error> {
        let cid = self
            .storage
            .upload(proof.clone().into_inner(), advertise)
            .await?;
        let tree = self.storage.manifest(cid).await?.tree_cid;
        self.proofs.insert(proof);
        let object = Object {
            digest: proof.digest(),
            cid,
            tree,
            released_at: None,
        };
        self.persist(&object).await?;
        self.lock().objects.insert(object.digest, object);
        Ok(cid)
    }

    async fn persist(&self, object: &Object) -> Result<(), Error> {
        let bytes = borsh::to_vec(object).expect("a proof object serializes");
        self.records
            .put(object.digest, bytes)
            .await
            .map_err(Error::Record)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl<S: StorageActorTrait> ObjectRecords for ActorRef<S> {
    async fn load(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self.ask(GetProofObjects).await?)
    }

    async fn put(&self, digest: ProofDigest, bytes: Vec<u8>) -> anyhow::Result<()> {
        Ok(self.ask(PutProofObject { digest, bytes }).await?)
    }

    async fn delete(&self, digest: ProofDigest) -> anyhow::Result<()> {
        Ok(self.ask(DeleteProofObject { digest }).await?)
    }
}

/// Seconds since the epoch, now.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
