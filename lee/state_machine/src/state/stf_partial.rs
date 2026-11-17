//! STF prototype: which public accounts a block touches, and the state split into its public
//! accounts (committed by a Merkle tree) and the rest (committed by a flat hash).

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};

use lee_core::account::{Account, AccountId};
use rpds::HashTrieMapSync;

use super::V03State;

thread_local! {
    /// The accounts read or written since tracking started, and whether tracking is paused.
    static TOUCHED: RefCell<(Option<BTreeSet<AccountId>>, bool)> = const { RefCell::new((None, false)) };
}

/// Starts recording the public accounts this thread reads or writes.
pub fn start_tracking() {
    TOUCHED.with(|t| *t.borrow_mut() = (Some(BTreeSet::new()), false));
}

/// Stops recording, returning every account touched.
#[must_use]
pub fn take_tracked() -> BTreeSet<AccountId> {
    TOUCHED.with(|t| t.borrow_mut().0.take()).unwrap_or_default()
}

pub(crate) fn note(account_id: AccountId) {
    TOUCHED.with(|t| {
        if let (Some(touched), false) = &mut *t.borrow_mut() {
            touched.insert(account_id);
        }
    });
}

/// Runs `f` without recording what it touches.
#[cfg_attr(target_os = "zkvm", allow(dead_code))]
pub(crate) fn paused<T>(f: impl FnOnce() -> T) -> T {
    let was = TOUCHED.with(|t| std::mem::replace(&mut t.borrow_mut().1, true));
    let out = f();
    TOUCHED.with(|t| t.borrow_mut().1 = was);
    out
}

impl V03State {
    /// Every public account, unordered.
    pub fn stf_public_accounts(&self) -> impl Iterator<Item = (&AccountId, &Account)> {
        self.public_state.iter()
    }

    /// This state without its public accounts: the part a flat hash commits.
    #[must_use]
    pub fn stf_without_public(&self) -> Self {
        Self {
            public_state: HashTrieMapSync::new_sync(),
            ..self.clone()
        }
    }

    /// The public account at `account_id`, without recording the read.
    #[must_use]
    pub fn stf_peek(&self, account_id: AccountId) -> Option<&Account> {
        self.public_state.get(&account_id)
    }
}

/// A signature check the guest skipped, left for whoever verifies the proof.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DeferredSignature {
    pub public_key: [u8; 32],
    pub message_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl DeferredSignature {
    /// The check the guest skipped.
    #[must_use]
    pub fn verify(&self) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
        let Ok(public_key) = k256::schnorr::VerifyingKey::from_bytes(&self.public_key) else {
            return false;
        };
        let Ok(signature) = k256::schnorr::Signature::try_from(self.signature.as_slice()) else {
            return false;
        };
        public_key.verify_prehash(&self.message_hash, &signature).is_ok()
    }
}

thread_local! {
    static DEFERRED: RefCell<Option<Vec<DeferredSignature>>> = const { RefCell::new(None) };
}

/// From now on every signature check passes and is recorded instead.
pub fn defer_signatures() {
    DEFERRED.with(|deferred| *deferred.borrow_mut() = Some(Vec::new()));
}

/// The recorded checks, sorted and without repeats; stops deferring.
pub fn take_deferred() -> Vec<DeferredSignature> {
    let mut taken = DEFERRED.with(|deferred| deferred.borrow_mut().take().unwrap_or_default());
    taken.sort_unstable();
    taken.dedup();
    taken
}

/// Records the check and returns true if signature checks are being deferred.
pub(crate) fn defer(public_key: &[u8; 32], message_hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    DEFERRED.with(|deferred| {
        deferred.borrow_mut().as_mut().is_some_and(|recorded| {
            recorded.push(DeferredSignature {
                public_key: *public_key,
                message_hash: *message_hash,
                signature: *signature,
            });
            true
        })
    })
}

thread_local! {
    static HASH_KEYS: Cell<bool> = const { Cell::new(false) };
}

/// From now on a public key is any 32 bytes: the hash of a secret, not a curve point.
pub fn use_hash_keys() {
    HASH_KEYS.with(|on| on.set(true));
}

pub(crate) fn hash_keys() -> bool {
    HASH_KEYS.with(Cell::get)
}
