use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{ErrorKind, Write as _},
    path::PathBuf,
};

use anyhow::{Context as _, Result};
use lee_core::{BlockId, Nullifier};

const COUNT_LEN: usize = 4;
const NULLIFIER_LEN: usize = 32;

pub struct SpentNullifiers {
    path: PathBuf,
    record_ends: Vec<u64>,
    spent: HashSet<Nullifier>,
}

impl SpentNullifiers {
    pub fn open(path: PathBuf) -> Result<Self> {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(error).with_context(|| format!("Failed to read {}", path.display()));
            }
        };
        let mut cache = Self {
            path,
            record_ends: Vec::new(),
            spent: HashSet::new(),
        };
        let mut rest = bytes.as_slice();
        while let Some((count, tail)) = rest.split_first_chunk::<COUNT_LEN>()
            && let Some((record, tail)) = usize::try_from(u32::from_le_bytes(*count))
                .ok()
                .and_then(|count| count.checked_mul(NULLIFIER_LEN))
                .and_then(|len| tail.split_at_checked(len))
        {
            cache.spent.extend(
                record
                    .as_chunks::<NULLIFIER_LEN>()
                    .0
                    .iter()
                    .copied()
                    .map(Nullifier::from_byte_array),
            );
            rest = tail;
            let end = bytes
                .len()
                .checked_sub(rest.len())
                .expect("rest ends bytes");
            cache.record_ends.push(u64::try_from(end)?);
        }
        Ok(cache)
    }

    #[must_use]
    pub fn covered(&self) -> BlockId {
        u64::try_from(self.record_ends.len()).expect("a record per block fits u64")
    }

    #[must_use]
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.spent.contains(nullifier)
    }

    pub fn keep(&mut self, blocks: BlockId) -> Result<()> {
        if blocks >= self.covered() {
            return Ok(());
        }
        self.record_ends.truncate(usize::try_from(blocks)?);
        self.truncated(OpenOptions::new().write(true))?
            .sync_data()?;
        *self = Self::open(self.path.clone())?;
        Ok(())
    }

    pub fn append(&mut self, nullifiers: Vec<Nullifier>) -> Result<()> {
        let mut record = u32::try_from(nullifiers.len())?.to_le_bytes().to_vec();
        for nullifier in &nullifiers {
            record.extend_from_slice(&nullifier.to_byte_array());
        }
        let end = self
            .end()
            .checked_add(u64::try_from(record.len())?)
            .context("Spent nullifiers overflow the cache")?;
        let mut file = self.truncated(OpenOptions::new().create(true).append(true))?;
        file.write_all(&record)?;
        file.sync_data()?;
        self.record_ends.push(end);
        self.spent.extend(nullifiers);
        Ok(())
    }

    fn end(&self) -> u64 {
        self.record_ends.last().copied().unwrap_or(0)
    }

    fn truncated(&self, options: &OpenOptions) -> Result<File> {
        let file = options
            .open(&self.path)
            .with_context(|| format!("Failed to open {}", self.path.display()))?;
        file.set_len(self.end())?;
        Ok(file)
    }
}
