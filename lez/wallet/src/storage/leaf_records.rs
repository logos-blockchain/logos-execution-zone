//! Which WOTS+ leaf each public account signs with next. A leaf is spent once its signature leaves
//! the wallet, so the record is saved before a transaction is sent, never after.
//!
//! Per account: how many signatures were sent with each tree, kept for every tree so a rollback
//! to an earlier one never reuses a leaf, and whether leaves are taken from the end of the tree
//! (an account this wallet did not create, whose earlier leaves another wallet may have used).
//! A tree is the key at `(nonce, counter)`: a manual rotation moves to a fresh tree at the same
//! nonce.
//! Counters only: nothing here is secret.

use std::{
    collections::BTreeMap,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use lee::AccountId;
use lee_core::account::Nonce;
use serde::{Deserialize, Serialize};

const LEAVES: u8 = lee::signature::WOTS_LEAVES;

/// Where an account takes leaves from the end of the tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Foreign {
    #[default]
    No,
    /// A restored or imported account: at whatever nonce it first signs at.
    NextSigned,
    At(u128),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct AccountLeaves {
    /// Signatures sent with each tree, by nonce, then counter.
    spent: BTreeMap<u128, BTreeMap<u32, u8>>,
    foreign: Foreign,
}

impl AccountLeaves {
    fn attempts(&self, nonce: Nonce, counter: u32) -> u8 {
        self.spent
            .get(&nonce.0)
            .and_then(|trees| trees.get(&counter))
            .copied()
            .unwrap_or(0)
    }

    fn sent_at(&self, nonce: Nonce) -> bool {
        self.spent
            .get(&nonce.0)
            .is_some_and(|trees| trees.values().any(|&attempts| attempts > 0))
    }

    const fn descending(&self, nonce: Nonce) -> bool {
        match self.foreign {
            Foreign::No => false,
            Foreign::NextSigned => true,
            Foreign::At(at) => at == nonce.0,
        }
    }

    fn leaf(&self, nonce: Nonce, counter: u32) -> Option<u8> {
        let last = LEAVES.checked_sub(1)?;
        let attempts = self.attempts(nonce, counter);
        if self.descending(nonce) {
            last.checked_sub(attempts)
        } else {
            (attempts <= last).then_some(attempts)
        }
    }

    fn spend(&mut self, nonce: Nonce, counter: u32) {
        if self.foreign == Foreign::NextSigned {
            self.foreign = Foreign::At(nonce.0);
        }
        let attempts = self
            .spent
            .entry(nonce.0)
            .or_default()
            .entry(counter)
            .or_insert(0);
        *attempts = attempts.saturating_add(1);
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeafError {
    #[error(
        "Account {account} has signed {LEAVES} transactions at nonce {} (rotation counter \
         {counter}), its every one-time key: wait for one to be included",
        nonce.0
    )]
    Exhausted {
        account: AccountId,
        nonce: Nonce,
        counter: u32,
    },
}

pub struct LeafRecords {
    path: PathBuf,
    records: BTreeMap<AccountId, AccountLeaves>,
}

impl LeafRecords {
    pub fn open(path: PathBuf) -> Result<Self> {
        let records = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("Failed to parse {}", path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => {
                return Err(error).with_context(|| format!("Failed to read {}", path.display()));
            }
        };
        Ok(Self { path, records })
    }

    /// Whether a signature by `account` was already sent at `nonce`, with any tree.
    #[must_use]
    pub fn sent_at(&self, account: AccountId, nonce: Nonce) -> bool {
        self.records
            .get(&account)
            .is_some_and(|leaves| leaves.sent_at(nonce))
    }

    /// The leaf `account`'s next signature with the tree at `(nonce, counter)` uses.
    pub fn next_leaf(
        &self,
        account: AccountId,
        nonce: Nonce,
        counter: u32,
    ) -> Result<u8, LeafError> {
        self.records
            .get(&account)
            .map_or(Some(0), |leaves| leaves.leaf(nonce, counter))
            .ok_or(LeafError::Exhausted {
                account,
                nonce,
                counter,
            })
    }

    /// Spends the next leaf of each `(account, nonce, counter)` and saves, before the signatures
    /// are sent.
    pub fn spend(&mut self, signers: &[(AccountId, Nonce, u32)]) -> Result<()> {
        for &(account, nonce, counter) in signers {
            self.records
                .entry(account)
                .or_default()
                .spend(nonce, counter);
        }
        self.save()
    }

    /// Marks an account this wallet did not create: it takes leaves from the end of the tree at
    /// `nonce`, or at whatever nonce it next signs at, unless it already has a record.
    pub fn mark_foreign(&mut self, account: AccountId, nonce: Option<Nonce>) -> Result<()> {
        if self.records.contains_key(&account) {
            return Ok(());
        }
        self.records.insert(
            account,
            AccountLeaves {
                spent: BTreeMap::new(),
                foreign: nonce.map_or(Foreign::NextSigned, |nonce| Foreign::At(nonce.0)),
            },
        );
        self.save()
    }

    /// Written to a temporary file, then renamed over the old one, so a crash leaves either.
    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.records)?;
        let temporary = temporary_path(&self.path);
        std::fs::write(&temporary, bytes)
            .with_context(|| format!("Failed to write {}", temporary.display()))?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, &self.path)
            .with_context(|| format!("Failed to replace {}", self.path.display()))
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = AccountId::new([1; 32]);

    fn records() -> (LeafRecords, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            LeafRecords::open(dir.path().join("wallet.leaves")).unwrap(),
            dir,
        )
    }

    #[test]
    fn leaves_are_taken_in_order_and_start_over_at_a_new_nonce() {
        let (mut records, _dir) = records();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 0), Ok(0));
        assert!(!records.sent_at(ACCOUNT, Nonce(4)));

        records.spend(&[(ACCOUNT, Nonce(4), 0)]).unwrap();
        assert!(records.sent_at(ACCOUNT, Nonce(4)));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 0), Ok(1));

        assert_eq!(records.next_leaf(ACCOUNT, Nonce(5), 0), Ok(0));
        assert!(!records.sent_at(ACCOUNT, Nonce(5)));
    }

    #[test]
    fn a_nonce_runs_out_after_every_leaf_is_spent() {
        let (mut records, _dir) = records();
        for _ in 0..LEAVES {
            records.spend(&[(ACCOUNT, Nonce(0), 0)]).unwrap();
        }
        assert_eq!(
            records.next_leaf(ACCOUNT, Nonce(0), 0),
            Err(LeafError::Exhausted {
                account: ACCOUNT,
                nonce: Nonce(0),
                counter: 0,
            })
        );
    }

    #[test]
    fn a_foreign_account_counts_down_at_its_first_nonce_only() {
        let (mut records, _dir) = records();
        records.mark_foreign(ACCOUNT, None).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(9), 0), Ok(7));
        records.spend(&[(ACCOUNT, Nonce(9), 0)]).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(9), 0), Ok(6));

        // A later nonce has nothing a lost wallet could have used.
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(10), 0), Ok(0));
    }

    #[test]
    fn marking_a_known_account_foreign_keeps_its_record() {
        let (mut records, _dir) = records();
        records.spend(&[(ACCOUNT, Nonce(2), 0)]).unwrap();
        records.mark_foreign(ACCOUNT, Some(Nonce(2))).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(2), 0), Ok(1));
    }

    #[test]
    fn a_foreign_account_marked_at_a_nonce_counts_down_there_only() {
        let (mut records, _dir) = records();
        records.mark_foreign(ACCOUNT, Some(Nonce(4))).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 0), Ok(7));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(5), 0), Ok(0));
    }

    #[test]
    fn a_rollback_to_an_earlier_nonce_takes_its_next_unspent_leaf() {
        let (mut records, _dir) = records();
        records.spend(&[(ACCOUNT, Nonce(4), 0)]).unwrap();
        records.spend(&[(ACCOUNT, Nonce(5), 0)]).unwrap();
        assert!(records.sent_at(ACCOUNT, Nonce(4)));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 0), Ok(1));
    }

    #[test]
    fn a_foreign_account_still_counts_down_after_a_rollback_to_its_first_nonce() {
        let (mut records, _dir) = records();
        records.mark_foreign(ACCOUNT, None).unwrap();
        records.spend(&[(ACCOUNT, Nonce(9), 0)]).unwrap();
        records.spend(&[(ACCOUNT, Nonce(10), 0)]).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(10), 0), Ok(1));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(9), 0), Ok(6));
    }

    #[test]
    fn records_survive_reopening() {
        let (mut records, dir) = records();
        records.spend(&[(ACCOUNT, Nonce(3), 0)]).unwrap();
        let reopened = LeafRecords::open(dir.path().join("wallet.leaves")).unwrap();
        assert_eq!(reopened.next_leaf(ACCOUNT, Nonce(3), 0), Ok(1));
    }

    #[test]
    fn a_manual_rotation_starts_a_fresh_tree() {
        let (mut records, _dir) = records();
        for _ in 0..LEAVES {
            records.spend(&[(ACCOUNT, Nonce(4), 0)]).unwrap();
        }
        assert!(records.next_leaf(ACCOUNT, Nonce(4), 0).is_err());
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 1), Ok(0));
    }

    #[test]
    fn trees_at_one_nonce_are_counted_separately() {
        let (mut records, _dir) = records();
        records.spend(&[(ACCOUNT, Nonce(4), 1)]).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 0), Ok(0));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 1), Ok(1));

        // A manual rotation that never lands: the wallet keeps signing with the first tree.
        records.spend(&[(ACCOUNT, Nonce(4), 0)]).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 0), Ok(1));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 1), Ok(1));
        assert!(records.sent_at(ACCOUNT, Nonce(4)));
    }

    #[test]
    fn a_foreign_account_counts_down_on_its_current_tree() {
        let (mut records, _dir) = records();
        records.mark_foreign(ACCOUNT, Some(Nonce(4))).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4), 1), Ok(7));
    }
}
