//! Process-global cache of built `MemoryImage`s, keyed by the ELF bytes themselves.
//!
//! Keyed on bytes rather than `Program::id`, which `Program::new_unchecked` lets diverge: serving
//! an image built from bytes other than the ones being charged for is a consensus fault. A
//! per-process seeded hash picks the slot and a full byte comparison confirms it, so a collision
//! skips the cache rather than returning the wrong image.

use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::{BuildHasher as _, Hasher as _},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use anyhow::{Result, bail};
use risc0_binfmt::{AbiKind, MemoryImage, ProgramBinary, ProgramBinaryHeader};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, NullSegmentRef};

use super::SessionOutcome;

#[cfg(test)]
mod tests;

/// Bytes held at once. Programs are user-deployable, so the budget is bytes rather than a count
/// of entries, and the least recently used entry is evicted first.
const MAX_CACHED_BYTES: usize = 32 * 1024 * 1024;

/// Mirrors risc0's private `check_program_version`: a different value would accept guests the
/// proving path rejects.
const SUPPORTED_ABI: &str = "^1.0.0";

struct Entry {
    elf: Box<[u8]>,
    image: Arc<MemoryImage>,
    bytes: usize,
    used: u64,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<u64, Entry>,
    bytes: usize,
    tick: u64,
}

fn cache() -> MutexGuard<'static, Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE
        .get_or_init(|| Mutex::new(Cache::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Slot selector over the whole ELF, seeded once per process so colliding bytes cannot be
/// constructed by whoever supplies the program.
pub fn slot(elf: &[u8]) -> u64 {
    static SEED: OnceLock<RandomState> = OnceLock::new();
    let mut hasher = SEED.get_or_init(RandomState::new).build_hasher();
    hasher.write(elf);
    hasher.finish()
}

/// What an entry costs to hold: the ELF copy plus its image. An upper bound, not a measurement,
/// since `MemoryImage` does not expose its size and measured images come in under their ELF. Only
/// moves when eviction starts.
const fn footprint(elf: &[u8]) -> usize {
    elf.len().saturating_mul(2)
}

/// The image for these exact bytes, marked most recently used. A slot holding different bytes is
/// a miss, never a substitution.
fn cached(key: u64, elf: &[u8]) -> Option<Arc<MemoryImage>> {
    let mut guard = cache();
    guard.tick = guard.tick.wrapping_add(1);
    let tick = guard.tick;
    let entry = guard.entries.get_mut(&key)?;
    if &*entry.elf != elf {
        return None;
    }
    entry.used = tick;
    Some(Arc::clone(&entry.image))
}

/// Records an image that has just executed cleanly, evicting to stay inside the budget.
fn remember(key: u64, elf: &[u8], image: &Arc<MemoryImage>) {
    let bytes = footprint(elf);
    if bytes > MAX_CACHED_BYTES {
        return;
    }
    let mut guard = cache();
    if guard.entries.contains_key(&key) {
        return;
    }
    while guard.bytes.saturating_add(bytes) > MAX_CACHED_BYTES {
        let Some(victim) = guard
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.used)
            .map(|(slot, _)| *slot)
        else {
            break;
        };
        if let Some(evicted) = guard.entries.remove(&victim) {
            guard.bytes = guard.bytes.saturating_sub(evicted.bytes);
        }
    }
    guard.tick = guard.tick.wrapping_add(1);
    let used = guard.tick;
    guard.bytes = guard.bytes.saturating_add(bytes);
    guard.entries.insert(
        key,
        Entry {
            elf: elf.into(),
            image: Arc::clone(image),
            bytes,
            used,
        },
    );
}

/// `ExecutorImpl::from_elf` runs this before building the image; `ExecutorImpl::new` does not, so
/// the cached path has to do it itself or an incompatible guest would silently start executing.
fn check_program_version(header: &ProgramBinaryHeader) -> Result<()> {
    if header.abi_kind != AbiKind::V1Compat {
        bail!(
            "ProgramBinary abi_kind mismatch {:?} != AbiKind::V1Compat",
            header.abi_kind
        );
    }
    if !semver::VersionReq::parse(SUPPORTED_ABI)
        .expect("static requirement parses")
        .matches(&header.abi_version)
    {
        bail!(
            "ProgramBinary abi_version mismatch {} doesn't match {SUPPORTED_ABI}",
            header.abi_version
        );
    }
    Ok(())
}

/// In-process no-proof execution against the cached image.
///
/// Mirrors `<LocalProver as Executor>::execute`, except the image comes from the cache and a
/// malformed ELF is returned as an error instead of panicking.
pub fn execute(env: ExecutorEnv<'_>, elf: &[u8]) -> Result<SessionOutcome> {
    let key = slot(elf);
    let image = if let Some(image) = cached(key, elf) {
        image
    } else {
        let binary = ProgramBinary::decode(elf)?;
        check_program_version(&binary.header)?;
        Arc::new(binary.to_image()?)
    };

    let session = ExecutorImpl::new(env, (*image).clone())?
        .run_with_callback(|_| Ok(Box::new(NullSegmentRef)))?;
    // The replaced path builds the claim and propagates its failure; a session it would reject
    // must not be accepted here.
    session.claim()?;

    // Only after a clean run: caching on the way in lets one cheap failing call pin an entry.
    remember(key, elf, &image);

    Ok(SessionOutcome {
        journal: session
            .journal
            .map(|journal| journal.bytes)
            .unwrap_or_default(),
        cycles: session.user_cycles,
    })
}
