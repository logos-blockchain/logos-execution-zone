//! STF prototype: which public accounts a block touches, and the state split into its public
//! accounts (committed by a Merkle tree) and the rest (committed by a flat hash).

use std::{cell::RefCell, collections::BTreeSet};

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
