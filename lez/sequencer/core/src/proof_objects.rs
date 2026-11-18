//! The proofs this node holds in Logos Storage, by LEZ digest.
//!
//! An object is held while the proof store has its proof, pinned by a chain entry or cached, or
//! until the expiry of its last hold: a mempool entry's or an approval's promise. Once released it
//! is served for the serving window more, then deleted. Every CID the map keeps is the one this
//! node's own canonical upload of verified bytes returned, so no peer's hint enters it.

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

/// How long a mempool entry holds its proof's object.
pub const MEMPOOL_HOLD: Duration = Duration::from_hours(1);

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
    #[error("this node holds no object of the proof")]
    NotHeld,
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
    /// Free bytes optional admission leaves: the live reserve and every download in flight.
    optional_floor: u64,
    max_downloads_per_peer: usize,
    downloads: Semaphore,
    /// Taken by every store and by a sweep's deletions, so neither undoes the other.
    writes: tokio::sync::Mutex<()>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<ProofDigest, Object>,
    peer_downloads: BTreeMap<PeerId, usize>,
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
    /// Seconds since the epoch until which a hold keeps the object.
    held_until: u64,
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
        let in_flight = u64::try_from(config.max_downloads)
            .unwrap_or(u64::MAX)
            .saturating_mul(OBJECT_BYTES);
        Self {
            storage,
            proofs,
            records,
            serving_window: config.serving_window,
            renewal_interval: config.renewal_interval,
            optional_floor: config.live_reserve_bytes.saturating_add(in_flight),
            max_downloads_per_peer: config.max_downloads_per_peer,
            downloads: Semaphore::new(config.max_downloads),
            writes: tokio::sync::Mutex::new(()),
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

    /// The proof `digest` names, from memory or else from the object this node holds, which the
    /// proof store then keeps.
    pub async fn get(&self, digest: &ProofDigest) -> Option<Proof> {
        if let Some(proof) = self.proofs.get(digest) {
            return Some(proof);
        }
        let cid = self.locator(digest)?;
        let bytes = self.storage.download(cid, PROOF_BYTES, true).await.ok()?;
        let proof = Proof::from_inner(bytes);
        if proof.digest() != *digest {
            return None;
        }
        self.proofs.insert(&proof);
        Some(proof)
    }

    /// Stores `proof` in the canonical form, served to peers, and returns its CID. The proof
    /// enters the proof store, which holds the object.
    pub async fn seed(&self, proof: &Proof) -> Result<StorageCid, Error> {
        self.store(proof, true, unix_now()).await
    }

    /// [`Self::seed`] for a transaction this node admitted, which its mempool entry holds: bounded
    /// as a peer's download is, and refused once only the live reserve is free.
    pub async fn seed_admitted(&self, proof: &Proof) -> Result<StorageCid, Error> {
        if !self.has_room().await? {
            return Err(Error::Full);
        }
        let _permit = self
            .downloads
            .try_acquire()
            .map_err(|_closed| Error::Busy)?;
        let cid = self.seed(proof).await?;
        self.hold(&proof.digest(), until(MEMPOOL_HOLD)).await?;
        Ok(cid)
    }

    /// The length of the proof the manifest `cid` names declares, read without advertising it and
    /// bounded as a peer's download is. A refused manifest is left to expire.
    pub async fn declared_len(&self, cid: StorageCid, peer: PeerId) -> Result<u64, Error> {
        if !self.has_room().await? {
            return Err(Error::Full);
        }
        let _permit = self
            .downloads
            .try_acquire()
            .map_err(|_closed| Error::Busy)?;
        let _peer = self.claim_peer(peer)?;
        let manifest = self.storage.manifest(cid).await?;
        self.serve_tree(cid, &manifest.tree_cid).await;
        manifest.check_canonical(PROOF_BYTES)?;
        Ok(manifest.dataset_size)
    }

    /// The proof `digest` names, from this node's own copy, else from the dataset `cid` names.
    /// Only a canonical manifest under the proof cap is followed, and only the exact proof
    /// `verify` accepts is kept: it is stored again in the canonical form, so the map takes this
    /// node's own CID.
    pub async fn fetch(
        &self,
        digest: ProofDigest,
        cid: StorageCid,
        admission: Admission,
        verify: impl FnOnce(&Proof) -> bool + Send,
    ) -> Result<Proof, Error> {
        let advertise = matches!(admission, Admission::Live);
        if let Some(proof) = self.get(&digest).await {
            if !verify(&proof) {
                return Err(Error::Unverified);
            }
            // Stored again, the whole payload is local under this node's CID; an object already
            // served is not stored unadvertised.
            if advertise || self.locator(&digest).is_none() {
                self.store(&proof, advertise, unix_now()).await?;
            }
            return Ok(proof);
        }
        if let Admission::Optional(_) = admission
            && !self.has_room().await?
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
        self.serve_tree(cid, &manifest.tree_cid).await;
        manifest.check_canonical(PROOF_BYTES)?;
        match self
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
                self.discard(cid, &manifest.tree_cid).await;
                Err(err)
            }
        }
    }

    /// Starts serving the object of `digest` to peers, once its transaction is admitted.
    pub async fn advertise(&self, digest: &ProofDigest) -> Result<(), Error> {
        if let Some(cid) = self.locator(digest) {
            self.storage.set_advertise(cid, true).await?;
        }
        Ok(())
    }

    /// Keeps the object of `digest` at least until `until`, seconds since the epoch, persisted
    /// before this returns.
    pub async fn hold(&self, digest: &ProofDigest, until: u64) -> Result<(), Error> {
        let _writes = self.writes.lock().await;
        let held = {
            let mut state = self.lock();
            let Some(object) = state.objects.get_mut(digest) else {
                return Err(Error::NotHeld);
            };
            object.held_until = object.held_until.max(until);
            object.released_at = None;
            object.clone()
        };
        self.persist(&held).await
    }

    /// Marks the objects held or released at `now` seconds since the epoch, renews the held ones
    /// stored a renewal interval ago and deletes the released ones whose serving window has
    /// closed.
    pub async fn sweep(&self, now: u64) -> Result<(), Error> {
        let window = self.serving_window.as_secs();
        let renewal = self.renewal_interval.as_secs();
        let renew: Vec<Object> = self
            .lock()
            .objects
            .values()
            .filter(|object| {
                self.is_held(object, now) && now.saturating_sub(object.stored_at) >= renewal
            })
            .cloned()
            .collect();
        for object in renew {
            if let Err(err) = self.renew(&object, now).await {
                warn!(cid = %object.cid, error = %err, "Failed to renew a held proof object");
            }
        }

        let _writes = self.writes.lock().await;
        let (changed, expired) = {
            let mut state = self.lock();
            let mut changed = Vec::new();
            for object in state.objects.values_mut() {
                let held = self.is_held(object, now);
                let released_at = (!held).then(|| object.released_at.unwrap_or(now));
                if released_at != object.released_at {
                    object.released_at = released_at;
                    changed.push(object.clone());
                }
            }
            let expired: Vec<Object> = state
                .objects
                .values()
                .filter(|object| {
                    object
                        .released_at
                        .is_some_and(|at| now.saturating_sub(at) >= window)
                })
                .cloned()
                .collect();
            for object in &expired {
                state.objects.remove(&object.digest);
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
            self.discard(object.cid, &object.tree).await;
        }
        Ok(())
    }

    /// Serves again the kept objects of `tree` but `cid`'s: fetching a manifest without
    /// advertising it stops serving its whole tree.
    async fn serve_tree(&self, cid: StorageCid, tree: &str) {
        let kept: Vec<StorageCid> = self
            .lock()
            .objects
            .values()
            .filter(|object| object.tree == tree && object.cid != cid)
            .map(|object| object.cid)
            .collect();
        for shared in kept {
            if let Err(err) = self.storage.set_advertise(shared, true).await {
                warn!(cid = %shared, error = %err, "Failed to serve a proof object again");
            }
        }
    }

    /// Bytes past the floor optional admission leaves.
    async fn has_room(&self) -> Result<bool, Error> {
        Ok(self.storage.free_bytes().await? >= self.optional_floor.saturating_add(OBJECT_BYTES))
    }

    fn is_held(&self, object: &Object, now: u64) -> bool {
        object.held_until > now || self.proofs.contains(&object.digest)
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

    /// Deletes the dataset `cid` names, unless a kept object shares its `tree`: deleting a
    /// manifest drops every block of its tree, and a zero-padded variant of a live proof shares
    /// that proof's tree. Only a canonical manifest is deleted, which names one block.
    async fn discard(&self, cid: StorageCid, tree: &str) {
        let shared = self
            .lock()
            .objects
            .values()
            .any(|object| object.cid == cid || object.tree == tree);
        if !shared
            && let Err(err) = self.storage.delete(cid).await
            && !err.is_not_found()
        {
            warn!(%cid, error = %err, "Failed to delete a proof object");
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
        let _writes = self.writes.lock().await;
        let cid = self
            .storage
            .upload(proof.clone().into_inner(), advertise)
            .await?;
        // An upload leaves in place the suppression an unadvertised fetch set.
        if advertise {
            self.storage.set_advertise(cid, true).await?;
        }
        let tree = self.storage.manifest(cid).await?.tree_cid;
        self.proofs.insert(proof);
        let held_until = self
            .lock()
            .objects
            .get(&proof.digest())
            .map_or(0, |held| held.held_until);
        let object = Object {
            digest: proof.digest(),
            cid,
            tree,
            stored_at: now,
            held_until,
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

/// Seconds since the epoch, `hold` from now.
#[must_use]
pub fn until(hold: Duration) -> u64 {
    unix_now().saturating_add(hold.as_secs())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use logos_storage::memory::{MemoryNetwork, MemoryStorage};
    use tokio::sync::Notify;

    use super::*;

    const WINDOW: u64 = 3600;
    const RENEWAL: u64 = 86_400;

    /// A node of `network` that can be scripted and counts what it is asked.
    #[derive(Default)]
    struct Scripted {
        node: Option<MemoryStorage>,
        manifest: Mutex<Option<Manifest>>,
        free: Mutex<Option<u64>>,
        /// Holds every payload download until notified.
        gate: Option<Arc<Notify>>,
        uploads: AtomicUsize,
        downloads: AtomicUsize,
        deletes: AtomicUsize,
    }

    impl Scripted {
        fn on(network: &MemoryNetwork) -> Self {
            Self {
                node: Some(network.node()),
                ..Self::default()
            }
        }

        fn node(&self) -> &MemoryStorage {
            self.node
                .as_ref()
                .expect("a scripted node runs on a network")
        }
    }

    #[async_trait]
    impl Storage for Scripted {
        async fn upload(
            &self,
            bytes: Vec<u8>,
            advertise: bool,
        ) -> Result<StorageCid, logos_storage::Error> {
            self.uploads.fetch_add(1, Ordering::Relaxed);
            self.node().upload(bytes, advertise).await
        }

        async fn manifest(&self, cid: StorageCid) -> Result<Manifest, logos_storage::Error> {
            let scripted = self.manifest.lock().unwrap().clone();
            match scripted {
                Some(manifest) => Ok(manifest),
                None => self.node().manifest(cid).await,
            }
        }

        async fn download(
            &self,
            cid: StorageCid,
            max_len: u64,
            local: bool,
        ) -> Result<Vec<u8>, logos_storage::Error> {
            if !local {
                self.downloads.fetch_add(1, Ordering::Relaxed);
                if let Some(gate) = &self.gate {
                    gate.notified().await;
                }
            }
            self.node().download(cid, max_len, local).await
        }

        async fn exists(&self, cid: StorageCid) -> Result<bool, logos_storage::Error> {
            self.node().exists(cid).await
        }

        async fn delete(&self, cid: StorageCid) -> Result<(), logos_storage::Error> {
            self.deletes.fetch_add(1, Ordering::Relaxed);
            self.node().delete(cid).await
        }

        async fn set_advertise(
            &self,
            cid: StorageCid,
            advertise: bool,
        ) -> Result<(), logos_storage::Error> {
            self.node().set_advertise(cid, advertise).await
        }

        async fn free_bytes(&self) -> Result<u64, logos_storage::Error> {
            let free = *self.free.lock().unwrap();
            Ok(free.unwrap_or(u64::MAX))
        }
    }

    fn config() -> LogosStorageConfig {
        LogosStorageConfig {
            serving_window: Duration::from_secs(WINDOW),
            renewal_interval: Duration::from_secs(RENEWAL),
            live_reserve_bytes: 1 << 30,
            max_downloads: 4,
            max_downloads_per_peer: 1,
            ..LogosStorageConfig::default()
        }
    }

    /// Objects over `storage`, whose proof store keeps nothing it is not told to pin.
    fn objects(storage: Arc<Scripted>, records: Arc<MemoryRecords>) -> ProofObjects {
        ProofObjects::new(storage, ProofStore::new(0), records, &config())
    }

    fn proof(fill: u8) -> Proof {
        Proof::from_inner(vec![fill; 64])
    }

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[tokio::test]
    async fn a_fetched_proof_is_kept_under_this_nodes_own_cid_and_served_once_its_seeder_is_gone() {
        let network = MemoryNetwork::default();
        let seeding = Arc::new(Scripted::on(&network));
        let seeder = objects(Arc::clone(&seeding), Arc::default());
        let fetching = Arc::new(Scripted::on(&network));
        let fetcher = objects(Arc::clone(&fetching), Arc::default());
        let cid = seeder.seed(&proof(1)).await.unwrap();

        let fetched = fetcher
            .fetch(proof(1).digest(), cid, Admission::Live, |_proof| true)
            .await
            .unwrap();
        seeding.node().set_online(false);

        assert_eq!(fetched, proof(1));
        assert_eq!(fetcher.locator(&proof(1).digest()), Some(cid));
        assert_eq!(fetching.downloads.load(Ordering::Relaxed), 1);
        assert!(network.node().download(cid, 64, false).await.is_ok());
    }

    #[tokio::test]
    async fn a_proof_held_in_memory_whose_payload_was_lost_is_stored_again_and_served() {
        let network = MemoryNetwork::default();
        let storage = Arc::new(Scripted::on(&network));
        let held = ProofObjects::new(
            Arc::<Scripted>::clone(&storage),
            ProofStore::new(usize::MAX),
            Arc::new(MemoryRecords::default()),
            &config(),
        );
        let cid = held.seed(&proof(1)).await.unwrap();
        storage.node().delete(cid).await.unwrap();

        held.fetch(proof(1).digest(), cid, Admission::Live, |_proof| true)
            .await
            .unwrap();

        assert_eq!(storage.downloads.load(Ordering::Relaxed), 0);
        assert!(network.node().download(cid, 64, false).await.is_ok());
    }

    #[tokio::test]
    async fn a_dataset_that_is_not_the_named_proof_is_refused_and_dropped() {
        let network = MemoryNetwork::default();
        let seeder = objects(Arc::new(Scripted::on(&network)), Arc::default());
        let fetching = Arc::new(Scripted::on(&network));
        let fetcher = objects(Arc::clone(&fetching), Arc::default());
        let other = seeder.seed(&proof(2)).await.unwrap();

        let refused = fetcher
            .fetch(proof(1).digest(), other, Admission::Live, |_proof| true)
            .await;

        assert!(matches!(refused, Err(Error::WrongProof)));
        assert_eq!(fetcher.locator(&proof(1).digest()), None);
        assert!(!fetching.node().holds(other));
    }

    #[tokio::test]
    async fn a_proof_that_does_not_verify_is_neither_kept_nor_served() {
        let network = MemoryNetwork::default();
        let seeder = objects(Arc::new(Scripted::on(&network)), Arc::default());
        let fetching = Arc::new(Scripted::on(&network));
        let fetcher = objects(Arc::clone(&fetching), Arc::default());
        let cid = seeder.seed(&proof(1)).await.unwrap();

        let refused = fetcher
            .fetch(proof(1).digest(), cid, Admission::Live, |_proof| false)
            .await;

        assert!(matches!(refused, Err(Error::Unverified)));
        assert_eq!(fetcher.locator(&proof(1).digest()), None);
        assert!(!fetching.node().holds(cid));
    }

    #[tokio::test]
    async fn a_manifest_of_another_form_is_refused_before_any_payload_is_downloaded() {
        let network = MemoryNetwork::default();
        let seeder = objects(Arc::new(Scripted::on(&network)), Arc::default());
        let fetching = Arc::new(Scripted::on(&network));
        let cid = seeder.seed(&proof(1)).await.unwrap();
        let named = Manifest {
            filename: Some("proof".to_owned()),
            ..fetching.node().manifest(cid).await.unwrap()
        };
        *fetching.manifest.lock().unwrap() = Some(named);
        let fetcher = objects(Arc::clone(&fetching), Arc::default());

        let refused = fetcher
            .fetch(proof(1).digest(), cid, Admission::Live, |_proof| true)
            .await;
        let declared = fetcher.declared_len(cid, peer()).await;

        assert!(matches!(
            refused,
            Err(Error::Storage(logos_storage::Error::NonCanonical(_)))
        ));
        assert!(matches!(
            declared,
            Err(Error::Storage(logos_storage::Error::NonCanonical(_)))
        ));
        assert_eq!(fetching.downloads.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_dataset_longer_than_the_proof_cap_is_refused_before_its_download() {
        let network = MemoryNetwork::default();
        let oversized = vec![1; usize::try_from(PROOF_BYTES).unwrap() + 1];
        let cid = network
            .node()
            .upload(oversized.clone(), true)
            .await
            .unwrap();
        let fetching = Arc::new(Scripted::on(&network));
        let fetcher = objects(Arc::clone(&fetching), Arc::default());

        let refused = fetcher
            .fetch(
                Proof::from_inner(oversized).digest(),
                cid,
                Admission::Live,
                |_proof| true,
            )
            .await;

        assert!(matches!(
            refused,
            Err(Error::Storage(logos_storage::Error::TooLong {
                max: PROOF_BYTES
            }))
        ));
        assert_eq!(fetching.downloads.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_peer_keeps_one_download_in_flight_and_the_reserve_turns_its_announcements_away() {
        let network = MemoryNetwork::default();
        let seeder = objects(Arc::new(Scripted::on(&network)), Arc::default());
        let gate = Arc::new(Notify::new());
        let fetching = Arc::new(Scripted {
            gate: Some(Arc::clone(&gate)),
            ..Scripted::on(&network)
        });
        let fetcher = Arc::new(objects(Arc::clone(&fetching), Arc::default()));
        let first = seeder.seed(&proof(1)).await.unwrap();
        let second = seeder.seed(&proof(2)).await.unwrap();
        let flooding = peer();

        let in_flight = tokio::spawn({
            let fetcher = Arc::clone(&fetcher);
            async move {
                fetcher
                    .fetch(
                        proof(1).digest(),
                        first,
                        Admission::Optional(flooding),
                        |_proof| true,
                    )
                    .await
            }
        });
        while fetching.downloads.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        let busy = fetcher
            .fetch(
                proof(2).digest(),
                second,
                Admission::Optional(flooding),
                |_proof| true,
            )
            .await;
        *fetching.free.lock().unwrap() = Some(1 << 30);
        let full = fetcher
            .fetch(
                proof(2).digest(),
                second,
                Admission::Optional(peer()),
                |_proof| true,
            )
            .await;
        gate.notify_one();

        assert!(matches!(busy, Err(Error::Busy)));
        assert!(matches!(full, Err(Error::Full)));
        assert!(in_flight.await.unwrap().is_ok());
        assert_eq!(fetching.downloads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_released_object_is_served_through_its_window_then_deleted() {
        let storage = Arc::new(Scripted::on(&MemoryNetwork::default()));
        let held = objects(Arc::clone(&storage), Arc::default());
        let cid = held.seed(&proof(1)).await.unwrap();

        held.sweep(1_000).await.unwrap();
        held.sweep(1_000 + WINDOW - 1).await.unwrap();
        assert_eq!(held.locator(&proof(1).digest()), Some(cid));
        assert!(storage.node().holds(cid));

        held.sweep(1_000 + WINDOW).await.unwrap();
        assert_eq!(held.locator(&proof(1).digest()), None);
        assert!(!storage.node().holds(cid));
    }

    #[tokio::test]
    async fn a_hold_keeps_an_object_past_its_window_and_renews_it() {
        let storage = Arc::new(Scripted::on(&MemoryNetwork::default()));
        let held = objects(Arc::clone(&storage), Arc::default());
        let cid = held.seed(&proof(1)).await.unwrap();
        let seeded = unix_now();
        held.hold(&proof(1).digest(), seeded + RENEWAL + WINDOW)
            .await
            .unwrap();

        held.sweep(seeded + RENEWAL - 1).await.unwrap();
        assert_eq!(storage.uploads.load(Ordering::Relaxed), 1);
        held.sweep(seeded + RENEWAL).await.unwrap();
        held.sweep(seeded + RENEWAL + WINDOW - 1).await.unwrap();
        assert!(storage.node().holds(cid));
        assert_eq!(storage.uploads.load(Ordering::Relaxed), 2);

        held.sweep(seeded + RENEWAL + WINDOW).await.unwrap();
        held.sweep(seeded + RENEWAL + 2 * WINDOW).await.unwrap();
        assert!(!storage.node().holds(cid));
    }

    #[tokio::test]
    async fn deleting_a_released_object_spares_the_tree_a_kept_one_shares() {
        let storage = Arc::new(Scripted::on(&MemoryNetwork::default()));
        let held = objects(Arc::clone(&storage), Arc::default());
        let kept = proof(1);
        let variant = Proof::from_inner([kept.clone().into_inner(), vec![0; 8]].concat());
        let kept_cid = held.seed(&kept).await.unwrap();
        let variant_cid = held.seed(&variant).await.unwrap();
        assert_eq!(
            storage.node().manifest(kept_cid).await.unwrap().tree_cid,
            storage.node().manifest(variant_cid).await.unwrap().tree_cid
        );
        held.hold(&kept.digest(), u64::MAX).await.unwrap();

        held.sweep(0).await.unwrap();
        held.sweep(WINDOW).await.unwrap();

        assert_eq!(held.locator(&variant.digest()), None);
        assert_eq!(storage.deletes.load(Ordering::Relaxed), 0);
        assert!(storage.node().holds(kept_cid));
    }

    #[tokio::test]
    async fn a_restart_restores_the_objects_the_node_still_holds_and_drops_the_rest() {
        let storage = Arc::new(Scripted::on(&MemoryNetwork::default()));
        let records = Arc::new(MemoryRecords::default());
        let before = objects(Arc::clone(&storage), Arc::clone(&records));
        let kept = before.seed(&proof(1)).await.unwrap();
        let lost = before.seed(&proof(2)).await.unwrap();
        before.hold(&proof(1).digest(), 2 * WINDOW).await.unwrap();
        storage.node().delete(lost).await.unwrap();

        let after = objects(Arc::clone(&storage), Arc::clone(&records));
        after.restore().await.unwrap();
        after.sweep(0).await.unwrap();
        after.sweep(WINDOW).await.unwrap();

        assert_eq!(after.locator(&proof(1).digest()), Some(kept));
        assert_eq!(after.locator(&proof(2).digest()), None);
        assert_eq!(records.load().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_proof_held_in_memory_is_served_by_digest_after_its_eviction_from_memory() {
        let storage = Arc::new(Scripted::on(&MemoryNetwork::default()));
        let proofs = ProofStore::new(64);
        let held = ProofObjects::new(
            Arc::<Scripted>::clone(&storage),
            proofs.clone(),
            Arc::new(MemoryRecords::default()),
            &config(),
        );
        held.seed(&proof(1)).await.unwrap();
        assert!(proofs.contains(&proof(1).digest()));

        held.seed(&proof(2)).await.unwrap();

        assert!(!proofs.contains(&proof(1).digest()));
        assert_eq!(held.get(&proof(1).digest()).await, Some(proof(1)));
        assert!(proofs.contains(&proof(1).digest()));
        assert_eq!(held.get(&proof(3).digest()).await, None);
    }

    #[tokio::test]
    async fn reading_another_manifest_of_a_kept_tree_does_not_stop_serving_it() {
        let network = MemoryNetwork::default();
        let held = objects(Arc::new(Scripted::on(&network)), Arc::default());
        let kept = proof(1);
        let cid = held.seed(&kept).await.unwrap();
        let variant = network
            .node()
            .upload([kept.into_inner(), vec![0; 8]].concat(), true)
            .await
            .unwrap();

        held.declared_len(variant, peer()).await.unwrap();

        assert!(network.node().download(cid, 64, false).await.is_ok());
    }

    #[tokio::test]
    async fn an_object_this_node_does_not_hold_cannot_be_promised() {
        let held = objects(
            Arc::new(Scripted::on(&MemoryNetwork::default())),
            Arc::default(),
        );

        assert!(matches!(
            held.hold(&proof(1).digest(), u64::MAX).await,
            Err(Error::NotHeld)
        ));
    }
}
