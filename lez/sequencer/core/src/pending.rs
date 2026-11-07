//! The mempool's pending index: which transaction holds each `(account, nonce)` slot, and the key
//! it commits its signer to at the next nonce. One pending transaction per slot, first seen wins.
//!
//! The index is this node's own view, so nothing it refuses is definitively invalid.

use std::collections::HashMap;

use common::{HashType, transaction::LeeTransaction};
use lee::{AccountId, public_transaction::WitnessEntry};
use lee_core::{account::Nonce, signing_key::SigningKeyState};

/// Why the index turns a transaction away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PendingRefusal {
    #[error("Account {account}'s nonce {} is already pending", nonce.0)]
    NoncePending { account: AccountId, nonce: Nonce },
    #[error("Account {account} already has {limit} pending transactions")]
    AccountLimit { account: AccountId, limit: usize },
}

/// Whether a transaction the index admits is new, or the very transaction already pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    New,
    Duplicate,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    tx_hash: HashType,
    next: SigningKeyState,
}

#[derive(Debug)]
pub struct PendingIndex {
    slots: HashMap<(AccountId, u128), Slot>,
    per_account: HashMap<AccountId, usize>,
    max_per_account: usize,
}

impl PendingIndex {
    #[must_use]
    pub fn new(max_per_account: usize) -> Self {
        Self {
            slots: HashMap::new(),
            per_account: HashMap::new(),
            max_per_account,
        }
    }

    /// The key a pending transaction commits `account` to at `nonce`: the next key of the one
    /// holding the slot just before it.
    #[must_use]
    pub fn key_at(&self, account: AccountId, nonce: Nonce) -> Option<SigningKeyState> {
        let previous = nonce.0.checked_sub(1)?;
        self.slots.get(&(account, previous)).map(|slot| slot.next)
    }

    /// Whether `tx` may enter: each slot it claims is free or already its own, and no signer's
    /// account is at its limit.
    pub fn check(&self, tx: &LeeTransaction) -> Result<Admission, PendingRefusal> {
        let tx_hash = tx.hash();
        let claimed = signer_slots(tx);
        let mut own = 0_usize;
        for (account, nonce, _) in &claimed {
            match self.slots.get(&(*account, nonce.0)) {
                Some(slot) if slot.tx_hash == tx_hash => own = own.saturating_add(1),
                Some(_) => {
                    return Err(PendingRefusal::NoncePending {
                        account: *account,
                        nonce: *nonce,
                    });
                }
                None => {}
            }
        }
        if !claimed.is_empty() && own == claimed.len() {
            return Ok(Admission::Duplicate);
        }
        for (account, _, _) in &claimed {
            if self.per_account.get(account).copied().unwrap_or(0) >= self.max_per_account {
                return Err(PendingRefusal::AccountLimit {
                    account: *account,
                    limit: self.max_per_account,
                });
            }
        }
        Ok(Admission::New)
    }

    /// Records the slots `tx` claims.
    pub fn insert(&mut self, tx: &LeeTransaction) {
        let tx_hash = tx.hash();
        for (account, nonce, next) in signer_slots(tx) {
            if self
                .slots
                .insert((account, nonce.0), Slot { tx_hash, next })
                .is_none()
            {
                let count = self.per_account.entry(account).or_insert(0);
                *count = count.saturating_add(1);
            }
        }
    }

    /// Frees the slots `tx` holds, when it leaves the mempool without being included.
    pub fn remove(&mut self, tx: &LeeTransaction) {
        let tx_hash = tx.hash();
        for (account, nonce, _) in signer_slots(tx) {
            if self
                .slots
                .get(&(account, nonce.0))
                .is_some_and(|slot| slot.tx_hash == tx_hash)
            {
                self.free((account, nonce.0));
            }
        }
    }

    /// Frees every slot below its account's nonce in `state`: its transaction, or another at the
    /// same nonce, has been included.
    pub fn prune(&mut self, state: &lee::V03State) {
        let stale: Vec<_> = self
            .slots
            .keys()
            .filter(|(account, nonce)| *nonce < account_nonce(state, *account).0)
            .copied()
            .collect();
        for slot in stale {
            self.free(slot);
        }
    }

    /// [`Self::prune`] for the accounts `tx` signs for only.
    pub fn prune_signers(&mut self, tx: &LeeTransaction, state: &lee::V03State) {
        for (account, _, _) in signer_slots(tx) {
            let head = account_nonce(state, account);
            let stale: Vec<_> = self
                .slots
                .keys()
                .filter(|(slot_account, nonce)| *slot_account == account && *nonce < head.0)
                .copied()
                .collect();
            for slot in stale {
                self.free(slot);
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    fn free(&mut self, slot: (AccountId, u128)) {
        if self.slots.remove(&slot).is_some()
            && let Some(count) = self.per_account.get_mut(&slot.0)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_account.remove(&slot.0);
            }
        }
    }
}

fn account_nonce(state: &lee::V03State, account: AccountId) -> Nonce {
    state
        .get_account_by_id_ref(account)
        .map_or_else(Nonce::default, |account| account.nonce)
}

/// Each signer's slot, and the key its witness entry rotates it to. Entries pair with `nonces` in
/// order; a transaction whose witness does not match claims nothing (it fails admission anyway).
fn signer_slots(tx: &LeeTransaction) -> Vec<(AccountId, Nonce, SigningKeyState)> {
    let (nonces, entries): (_, &[WitnessEntry]) = match tx {
        LeeTransaction::Public(tx) => (&tx.message().nonces, tx.witness_set().entries()),
        LeeTransaction::PrivacyPreserving(tx) => (&tx.message().nonces, tx.witness_set().entries()),
    };
    if nonces.len() != entries.len() {
        return Vec::new();
    }
    nonces
        .iter()
        .zip(entries)
        .map(|((&account, &nonce), entry)| (account, nonce, entry.next))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee::{
        Actor, PublicTransaction, V03State,
        public_transaction::Message,
        test_utils::{TestSigner, witness_for},
    };

    use super::*;

    fn transfer(signer: &TestSigner, nonce: u128, amount: u128) -> LeeTransaction {
        let sender = Actor::native_balance(signer.account_id());
        let recipient = Actor::native_balance(AccountId::new([9; 32]));
        let message = Message::try_new(
            sender,
            vec![sender, recipient],
            BTreeMap::from([(signer.account_id(), Nonce(nonce))]),
            lee_core::native_token::Message::Transfer {
                to: recipient.account_id,
                amount,
            },
        )
        .unwrap();
        let witness_set = witness_for(&message, &[signer]);
        PublicTransaction::new(message, witness_set).into()
    }

    #[test]
    fn a_pending_transaction_commits_its_signer_to_the_next_key() {
        let signer = TestSigner::new(1);
        let mut index = PendingIndex::new(16);
        assert_eq!(index.key_at(signer.account_id(), Nonce(1)), None);

        index.insert(&transfer(&signer, 0, 1));
        assert_eq!(
            index.key_at(signer.account_id(), Nonce(1)),
            Some(signer.key_state(Nonce(1)))
        );
        assert_eq!(index.key_at(signer.account_id(), Nonce(2)), None);
    }

    #[test]
    fn the_first_transaction_seen_holds_its_slot() {
        let signer = TestSigner::new(1);
        let mut index = PendingIndex::new(16);
        let first = transfer(&signer, 0, 1);
        index.insert(&first);

        assert_eq!(index.check(&first), Ok(Admission::Duplicate));
        assert_eq!(
            index.check(&transfer(&signer, 0, 2)),
            Err(PendingRefusal::NoncePending {
                account: signer.account_id(),
                nonce: Nonce(0),
            })
        );
        assert_eq!(index.check(&transfer(&signer, 1, 2)), Ok(Admission::New));
    }

    #[test]
    fn an_account_holds_at_most_its_limit_of_pending_transactions() {
        let signer = TestSigner::new(1);
        let mut index = PendingIndex::new(2);
        index.insert(&transfer(&signer, 0, 1));
        index.insert(&transfer(&signer, 1, 1));

        assert_eq!(
            index.check(&transfer(&signer, 2, 1)),
            Err(PendingRefusal::AccountLimit {
                account: signer.account_id(),
                limit: 2,
            })
        );
    }

    #[test]
    fn removing_a_transaction_frees_only_the_slots_it_holds() {
        let signer = TestSigner::new(1);
        let mut index = PendingIndex::new(16);
        let held = transfer(&signer, 0, 1);
        index.insert(&held);

        // Another transaction at the same slot does not free it.
        index.remove(&transfer(&signer, 0, 2));
        assert_eq!(index.len(), 1);

        index.remove(&held);
        assert!(index.is_empty());
        assert_eq!(index.check(&transfer(&signer, 0, 2)), Ok(Admission::New));
    }

    #[test]
    fn slots_below_the_head_nonce_are_pruned() {
        let signer = TestSigner::new(1);
        let mut index = PendingIndex::new(16);
        let first = transfer(&signer, 0, 1);
        index.insert(&first);
        index.insert(&transfer(&signer, 1, 1));

        let mut state = V03State::new().with_public_account_balances([
            (signer.account_id(), 100),
            (AccountId::new([9; 32]), 0),
        ]);
        let LeeTransaction::Public(first) = first else {
            unreachable!("a transfer is public");
        };
        state
            .transition_from_public_transaction(&first, 1, 0)
            .unwrap();

        index.prune(&state);
        assert_eq!(index.len(), 1);
        assert_eq!(index.key_at(signer.account_id(), Nonce(1)), None);
        assert_eq!(
            index.key_at(signer.account_id(), Nonce(2)),
            Some(signer.key_state(Nonce(2)))
        );
    }
}
