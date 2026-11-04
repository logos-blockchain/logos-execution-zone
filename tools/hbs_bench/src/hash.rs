//! SHA-256 wrappers that count compression-function calls.

use sha2::{Digest, Sha256};
use std::cell::Cell;

thread_local! {
    static COMPRESSIONS: Cell<u64> = const { Cell::new(0) };
}

pub fn reset_count() {
    COMPRESSIONS.with(|c| c.set(0));
}

pub fn count() -> u64 {
    COMPRESSIONS.with(|c| c.get())
}

fn add(blocks: u64) {
    COMPRESSIONS.with(|c| c.set(c.get() + blocks));
}

fn blocks(len: usize) -> u64 {
    ((len + 9).div_ceil(64)) as u64
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut len = 0;
    for p in parts {
        h.update(p);
        len += p.len();
    }
    add(blocks(len));
    h.finalize().into()
}

/// SHA-256 with a cached midstate over a fixed 64-byte first block
/// (e.g. `PK.seed || zero-pad` in FIPS 205).
#[derive(Clone)]
pub struct Seeded {
    st: Sha256,
}

impl Seeded {
    pub fn new(block: &[u8]) -> Self {
        assert_eq!(block.len(), 64);
        let mut st = Sha256::new();
        st.update(block);
        add(1);
        Self { st }
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let mut block = [0u8; 64];
        block[..seed.len()].copy_from_slice(seed);
        Self::new(&block)
    }

    #[inline]
    pub fn hash(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = self.st.clone();
        let mut len = 64;
        for p in parts {
            h.update(p);
            len += p.len();
        }
        add(blocks(len) - 1);
        h.finalize().into()
    }
}
