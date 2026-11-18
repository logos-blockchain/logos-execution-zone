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
use fee_core::market::PROOF_BYTES;
use kameo::actor::ActorRef;
use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};
use libp2p::PeerId;
use logos_storage::{BLOCK_SIZE, Manifest, Storage};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{DeleteProofObject, GetProofObjects, PutProofObject},
};
use tokio::sync::Semaphore;
use tracing::warn;

use crate::config::LogosStorageConfig;

/// Bytes one more object takes at most: its padded data block and its manifest's block.
const OBJECT_BYTES: u64 = 2 * BLOCK_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] logos_storage::Error),
    #[error("Failed to persist a proof object: {0:#}")]
    Record(anyhow::Error),
    #[error("the dataset is not the proof its digest names")]
    WrongProof,
    #[error("the proof does not verify")]
    Unverified,
    #[error("too many proof downloads in flight")]
    Busy,
    #[error("only the reserve for live blocks is free")]
    Full,
}

/// Why a proof is fetched.
#[derive(Debug, Clone, Copy)]
pub enum Admission {
    /// A peer's announcement: bounded per peer, refused once only the live reserve is free, and
    /// not served until admitted.
    Optional(PeerId),
    /// A proof a live block or this node's approval needs, served once verified.
    Live,
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
    renewal_interval: Duration,
    live_reserve_bytes: u64,
    max_downloads_per_peer: usize,
    downloads: Semaphore,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<ProofDigest, Object>,
    holds: BTreeMap<ProofDigest, usize>,
    peer_downloads: BTreeMap<PeerId, usize>,
    /// Refused datasets, by tree, whose deletion failed; retried on the next sweep.
    leftovers: BTreeMap<StorageCid, String>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct Object {
    digest: ProofDigest,
    cid: StorageCid,
    /// The manifest's tree, which another dataset can share: deleting either drops the other's
    /// blocks.
    tree: String,
    /// Seconds since the epoch of the upload that set the object's expiry.
    stored_at: u64,
    /// Seconds since the epoch when the last holder let go, if one did.
    released_at: Option<u64>,
}

impl ProofObjects {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        proofs: ProofStore,
        records: Arc<dyn ObjectRecords>,
        config: &LogosStorageConfig,
    ) -> Self {
        Self {
            storage,
            proofs,
            records,
            serving_window: config.serving_window,
            renewal_interval: config.renewal_interval,
            live_reserve_bytes: config.live_reserve_bytes,
            max_downloads_per_peer: config.max_downloads_per_peer,
            downloads: Semaphore::new(config.max_downloads),
            state: Mutex::new(State::default()),
        }
    }

    /// Objects on an in-memory Storage node of their own, with in-memory records.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn in_memory(proofs: ProofStore) -> Self {
        Self::new(
            Arc::new(logos_storage::memory::MemoryNetwork::default().node()),
            proofs,
            Arc::new(MemoryRecords::default()),
            &LogosStorageConfig::default(),
        )
    }

    /// Installs the map persisted before a restart, without the objects the node no longer
    /// holds.
    pub async fn restore(&self) -> Result<(), Error> {
        for bytes in self.records.load().await.map_err(Error::Record)? {
            let Ok(object) = Object::try_from_slice(&bytes) else {
                warn!("Skipping a persisted proof object that doesn't decode");
                continue;
            };
            // A node that cannot answer keeps the record, to be checked by the next restart.
            match self.storage.exists(object.cid).await {
                Ok(false) => self
                    .records
                    .delete(object.digest)
                    .await
                    .map_err(Error::Record)?,
                Ok(true) => {
                    self.lock().objects.insert(object.digest, object);
                }
                Err(err) => {
                    warn!(cid = %object.cid, error = %err, "Failed to reconcile a proof object");
                    self.lock().objects.insert(object.digest, object);
                }
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
        self.store(proof, true, unix_now()).await
    }

    /// The length of the proof the manifest `cid` names declares, read without advertising it and
    /// bounded as a peer's download is. A manifest of another form is dropped.
    pub async fn declared_len(&self, cid: StorageCid, peer: PeerId) -> Result<u64, Error> {
        let _permit = self
            .downloads
            .try_acquire()
            .map_err(|_closed| Error::Busy)?;
        let _peer = self.claim_peer(peer)?;
        let manifest = self.storage.manifest(cid).await?;
        if let Err(err) = manifest.check_canonical(PROOF_BYTES) {
            self.discard(cid, manifest.tree_cid).await;
            return Err(err.into());
        }
        Ok(manifest.dataset_size)
    }

    /// The proof `digest` names, from the dataset `cid` names unless held already. Only a
    /// canonical manifest under the proof cap is followed, and only the exact proof `verify`
    /// accepts is kept: it is stored again in the canonical form, so the map takes this node's
    /// own CID.
    pub async fn fetch(
        &self,
        digest: ProofDigest,
        cid: StorageCid,
        admission: Admission,
        verify: impl FnOnce(&Proof) -> bool + Send,
    ) -> Result<Proof, Error> {
        let advertise = matches!(admission, Admission::Live);
        if let Some(proof) = self.proofs.get(&digest) {
            if !verify(&proof) {
                return Err(Error::Unverified);
            }
            match self.locator(&digest) {
                None => {
                    self.store(&proof, advertise, unix_now()).await?;
                }
                Some(held) if advertise => self.storage.set_advertise(held, true).await?,
                Some(_) => {}
            }
            return Ok(proof);
        }
        if let Admission::Optional(_) = admission
            && self.storage.free_bytes().await?
                < self.live_reserve_bytes.saturating_add(OBJECT_BYTES)
        {
            return Err(Error::Full);
        }
        let _permit = self
            .downloads
            .try_acquire()
            .map_err(|_closed| Error::Busy)?;
        let _peer = match admission {
            Admission::Optional(peer) => Some(self.claim_peer(peer)?),
            Admission::Live => None,
        };
        let manifest = self.storage.manifest(cid).await?;
        self.hold(digest);
        let fetched = match self
            .download(digest, cid, &manifest)
            .await
            .and_then(|proof| {
                if verify(&proof) {
                    Ok(proof)
                } else {
                    Err(Error::Unverified)
                }
            }) {
            Ok(proof) => self
                .store(&proof, advertise, unix_now())
                .await
                .map(|_cid| proof),
            Err(err) => {
                self.discard(cid, manifest.tree_cid).await;
                Err(err)
            }
        };
        self.release(&digest);
        fetched
    }

    /// Starts serving the object of `digest` to peers, once its transaction is admitted.
    pub async fn advertise(&self, digest: &ProofDigest) -> Result<(), Error> {
        if let Some(cid) = self.locator(digest) {
            self.storage.set_advertise(cid, true).await?;
        }
        Ok(())
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

    /// Marks the objects held or released at `now` seconds since the epoch, renews the held ones
    /// stored a renewal interval ago and deletes the released ones whose serving window has
    /// closed.
    pub async fn sweep(&self, now: u64) -> Result<(), Error> {
        let window = self.serving_window.as_secs();
        let renewal = self.renewal_interval.as_secs();
        let (changed, renew, expired, leftovers) = {
            let mut state = self.lock();
            let State {
                objects,
                holds,
                leftovers,
                ..
            } = &mut *state;
            let mut changed = Vec::new();
            let mut renew = Vec::new();
            for object in objects.values_mut() {
                let held =
                    holds.contains_key(&object.digest) || self.proofs.contains(&object.digest);
                let released_at = (!held).then(|| object.released_at.unwrap_or(now));
                if released_at != object.released_at {
                    object.released_at = released_at;
                    changed.push(object.clone());
                }
                if held && now.saturating_sub(object.stored_at) >= renewal {
                    renew.push(object.clone());
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
            (changed, renew, expired, std::mem::take(leftovers))
        };
        for object in changed {
            self.persist(&object).await?;
        }
        for object in renew {
            if let Err(err) = self.renew(&object, now).await {
                warn!(cid = %object.cid, error = %err, "Failed to renew a held proof object");
            }
        }
        for (cid, tree) in leftovers {
            self.discard(cid, tree).await;
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

    /// Reads the proof back and uploads it again: Storage has no call that extends an expiry,
    /// and a store raises it.
    async fn renew(&self, object: &Object, now: u64) -> Result<(), Error> {
        let proof = match self.proofs.get(&object.digest) {
            Some(proof) => proof,
            None => Proof::from_inner(self.storage.download(object.cid, PROOF_BYTES, true).await?),
        };
        if proof.digest() != object.digest {
            return Err(Error::WrongProof);
        }
        self.store(&proof, true, now).await.map(|_cid| ())
    }

    async fn download(
        &self,
        digest: ProofDigest,
        cid: StorageCid,
        manifest: &Manifest,
    ) -> Result<Proof, Error> {
        manifest.check_canonical(PROOF_BYTES)?;
        let bytes = self
            .storage
            .download(cid, manifest.dataset_size, false)
            .await?;
        if u64::try_from(bytes.len()).ok() != Some(manifest.dataset_size) {
            return Err(Error::WrongProof);
        }
        let proof = Proof::from_inner(bytes);
        if proof.digest() != digest {
            return Err(Error::WrongProof);
        }
        Ok(proof)
    }

    /// Deletes what a refused fetch of `cid` left behind, unless a kept object shares its
    /// `tree`: deleting a manifest drops every block of its tree, and a zero-padded variant of a
    /// live proof shares that proof's tree.
    async fn discard(&self, cid: StorageCid, tree: String) {
        let shared = self
            .lock()
            .objects
            .values()
            .any(|object| object.cid == cid || object.tree == tree);
        if shared {
            return;
        }
        if let Err(err) = self.storage.delete(cid).await
            && !err.is_not_found()
        {
            warn!(%cid, error = %err, "Failed to delete a refused proof object");
            self.lock().leftovers.insert(cid, tree);
        }
    }

    fn claim_peer(&self, peer: PeerId) -> Result<PeerClaim<'_>, Error> {
        let mut state = self.lock();
        let downloads = state.peer_downloads.entry(peer).or_default();
        if *downloads >= self.max_downloads_per_peer {
            return Err(Error::Busy);
        }
        *downloads = downloads.saturating_add(1);
        Ok(PeerClaim {
            objects: self,
            peer,
        })
    }

    async fn store(&self, proof: &Proof, advertise: bool, now: u64) -> Result<StorageCid, Error> {
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
            stored_at: now,
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

/// One download a peer's announcement holds.
struct PeerClaim<'objects> {
    objects: &'objects ProofObjects,
    peer: PeerId,
}

impl Drop for PeerClaim<'_> {
    fn drop(&mut self) {
        let mut state = self.objects.lock();
        if let Some(downloads) = state.peer_downloads.get_mut(&self.peer) {
            *downloads = downloads.saturating_sub(1);
            if *downloads == 0 {
                state.peer_downloads.remove(&self.peer);
            }
        }
    }
}

/// Records kept in memory, for tests.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default)]
pub struct MemoryRecords(Mutex<BTreeMap<ProofDigest, Vec<u8>>>);

#[cfg(any(test, feature = "test-utils"))]
#[async_trait]
impl ObjectRecords for MemoryRecords {
    async fn load(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }

    async fn put(&self, digest: ProofDigest, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(digest, bytes);
        Ok(())
    }

    async fn delete(&self, digest: ProofDigest) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&digest);
        Ok(())
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
