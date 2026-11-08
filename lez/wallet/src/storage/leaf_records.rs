//! Which WOTS+ leaf each public account signs with next. A leaf is spent once its signature leaves
//! the wallet, so the record is saved before a transaction is sent, never after.
//!
//! Per account: the nonce the record is for, how many signatures were sent at it, and whether
//! leaves are taken from the end of the tree (an account this wallet did not create, whose earlier
//! leaves another wallet may have used). Counters only: nothing here is secret.

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct LeafRecord {
    /// `None` until the first signature: a restored or imported account's record applies to
    /// whatever nonce it first signs at.
    nonce: Option<u128>,
    attempts: u8,
    descending: bool,
}

impl LeafRecord {
    /// The record as it stands for a signature at `nonce`.
    const fn at(self, nonce: Nonce) -> Self {
        match self.nonce {
            Some(recorded) if recorded == nonce.0 => self,
            None => Self {
                nonce: Some(nonce.0),
                ..self
            },
            Some(_) => Self {
                nonce: Some(nonce.0),
                attempts: 0,
                descending: false,
            },
        }
    }

    fn leaf(self) -> Option<u8> {
        let last = LEAVES.checked_sub(1)?;
        if self.descending {
            last.checked_sub(self.attempts)
        } else {
            (self.attempts <= last).then_some(self.attempts)
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeafError {
    #[error(
        "Account {account} has signed {LEAVES} transactions at nonce {}, its every one-time key: \
         wait for one to be included",
        nonce.0
    )]
    Exhausted { account: AccountId, nonce: Nonce },
}

pub struct LeafRecords {
    path: PathBuf,
    records: BTreeMap<AccountId, LeafRecord>,
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

    /// Whether a signature by `account` was already sent at `nonce`.
    #[must_use]
    pub fn sent_at(&self, account: AccountId, nonce: Nonce) -> bool {
        self.record(account).at(nonce).attempts > 0
    }

    /// The leaf `account`'s next signature at `nonce` uses.
    pub fn next_leaf(&self, account: AccountId, nonce: Nonce) -> Result<u8, LeafError> {
        self.record(account)
            .at(nonce)
            .leaf()
            .ok_or(LeafError::Exhausted { account, nonce })
    }

    /// Spends the next leaf of each `(account, nonce)` and saves, before the signatures are sent.
    pub fn spend(&mut self, signers: &[(AccountId, Nonce)]) -> Result<()> {
        for &(account, nonce) in signers {
            let mut record = self.record(account).at(nonce);
            record.attempts = record.attempts.saturating_add(1);
            self.records.insert(account, record);
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
            LeafRecord {
                nonce: nonce.map(|nonce| nonce.0),
                attempts: 0,
                descending: true,
            },
        );
        self.save()
    }

    fn record(&self, account: AccountId) -> LeafRecord {
        self.records.get(&account).copied().unwrap_or_default()
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
    fn leaves_are_taken_in_order_and_reset_when_the_nonce_moves_on() {
        let (mut records, _dir) = records();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4)), Ok(0));
        assert!(!records.sent_at(ACCOUNT, Nonce(4)));

        records.spend(&[(ACCOUNT, Nonce(4))]).unwrap();
        assert!(records.sent_at(ACCOUNT, Nonce(4)));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4)), Ok(1));

        assert_eq!(records.next_leaf(ACCOUNT, Nonce(5)), Ok(0));
        assert!(!records.sent_at(ACCOUNT, Nonce(5)));
    }

    #[test]
    fn a_nonce_runs_out_after_every_leaf_is_spent() {
        let (mut records, _dir) = records();
        for _ in 0..LEAVES {
            records.spend(&[(ACCOUNT, Nonce(0))]).unwrap();
        }
        assert_eq!(
            records.next_leaf(ACCOUNT, Nonce(0)),
            Err(LeafError::Exhausted {
                account: ACCOUNT,
                nonce: Nonce(0)
            })
        );
    }

    #[test]
    fn a_foreign_account_counts_down_at_its_first_nonce_only() {
        let (mut records, _dir) = records();
        records.mark_foreign(ACCOUNT, None).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(9)), Ok(7));
        records.spend(&[(ACCOUNT, Nonce(9))]).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(9)), Ok(6));

        // A later nonce has nothing a lost wallet could have used.
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(10)), Ok(0));
    }

    #[test]
    fn marking_a_known_account_foreign_keeps_its_record() {
        let (mut records, _dir) = records();
        records.spend(&[(ACCOUNT, Nonce(2))]).unwrap();
        records.mark_foreign(ACCOUNT, Some(Nonce(2))).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(2)), Ok(1));
    }

    #[test]
    fn a_foreign_account_marked_at_a_nonce_counts_down_there_only() {
        let (mut records, _dir) = records();
        records.mark_foreign(ACCOUNT, Some(Nonce(4))).unwrap();
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(4)), Ok(7));
        assert_eq!(records.next_leaf(ACCOUNT, Nonce(5)), Ok(0));
    }

    #[test]
    fn records_survive_reopening() {
        let (mut records, dir) = records();
        records.spend(&[(ACCOUNT, Nonce(3))]).unwrap();
        let reopened = LeafRecords::open(dir.path().join("wallet.leaves")).unwrap();
        assert_eq!(reopened.next_leaf(ACCOUNT, Nonce(3)), Ok(1));
    }
}
