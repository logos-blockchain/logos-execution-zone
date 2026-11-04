//! One-time Winternitz signatures over incomparable encodings
//! (Drake–Khovratovich–Kudinov–Wagner, ePrint 2025/055), instantiated with SHA-256.
//!
//! Tweakable hash: `SHA-256(P || pad64 || tweak || x)[..n]` with a cached midstate for `P`.
//! The public key stored in the account is `(P, root)` where `root = Th(P, pk_tweak, chain ends)`.

use crate::hash::{Seeded, sha256};

#[derive(Clone, Copy, Debug)]
pub enum Enc {
    /// Target-sum: message-hash chunks must sum to exactly `T`.
    TargetSum(u32),
    /// Classic checksum Winternitz: `vm` message chunks + `vc` checksum chunks.
    Checksum { vm: usize, vc: usize },
}

#[derive(Clone, Debug)]
pub struct Params {
    pub name: String,
    pub chunk_bits: u32,
    pub v: usize,
    pub enc: Enc,
    pub n: usize,
    pub p_len: usize,
    pub rho_len: usize,
}

impl Params {
    pub fn base(&self) -> u32 {
        1 << self.chunk_bits
    }
    pub fn sig_len(&self) -> usize {
        self.rho_len + self.v * self.n
    }
    pub fn pk_len(&self) -> usize {
        self.p_len + self.n
    }
}

pub struct PublicKey {
    pub p: Vec<u8>,
    pub root: Vec<u8>,
}

fn chain_tweak(epoch: u32, chain: usize, pos: u32) -> [u8; 7] {
    let e = epoch.to_be_bytes();
    [0x00, e[0], e[1], e[2], e[3], chain as u8, pos as u8]
}

fn pk_tweak(epoch: u32) -> [u8; 5] {
    let e = epoch.to_be_bytes();
    [0x01, e[0], e[1], e[2], e[3]]
}

fn bits_to_chunks(bytes: &[u8], chunk_bits: u32, count: usize) -> Vec<u32> {
    let per_byte = 8 / chunk_bits as usize;
    let mask = (1u32 << chunk_bits) - 1;
    let mut out = Vec::with_capacity(count);
    'outer: for b in bytes {
        for j in 0..per_byte {
            if out.len() == count {
                break 'outer;
            }
            let shift = 8 - chunk_bits as usize * (j + 1);
            out.push((*b as u32 >> shift) & mask);
        }
    }
    assert_eq!(out.len(), count);
    out
}

impl Params {
    fn walk(&self, th: &Seeded, epoch: u32, chain: usize, x: &mut [u8; 32], from: u32, to: u32) {
        for pos in from..to {
            let t = chain_tweak(epoch, chain, pos + 1);
            *x = th.hash(&[&t, &x[..self.n]]);
        }
    }

    fn chain_start(&self, sk_seed: &[u8; 32], epoch: u32, chain: usize) -> [u8; 32] {
        sha256(&[sk_seed, &[0x03], &epoch.to_be_bytes(), &[chain as u8]])
    }

    /// Returns the codeword, or None if the encoding rejects this randomness.
    fn encode(&self, p: &[u8], rho: &[u8], epoch: u32, msg: &[u8; 32]) -> Option<Vec<u32>> {
        let d = sha256(&[rho, p, &[0x02], &epoch.to_be_bytes(), msg]);
        let w1 = self.base() - 1;
        match self.enc {
            Enc::TargetSum(t) => {
                let c = bits_to_chunks(&d, self.chunk_bits, self.v);
                (c.iter().sum::<u32>() == t).then_some(c)
            }
            Enc::Checksum { vm, vc } => {
                let mut c = bits_to_chunks(&d, self.chunk_bits, vm);
                let mut csum: u32 = c.iter().map(|x| w1 - x).sum();
                for _ in 0..vc {
                    c.push(csum % self.base());
                    csum /= self.base();
                }
                Some(c)
            }
        }
    }

    pub fn keygen(&self, sk_seed: &[u8; 32], p: &[u8], epoch: u32) -> PublicKey {
        let th = Seeded::from_seed(p);
        let mut ends = Vec::with_capacity(self.v * self.n);
        for i in 0..self.v {
            let mut x = self.chain_start(sk_seed, epoch, i);
            self.walk(&th, epoch, i, &mut x, 0, self.base() - 1);
            ends.extend_from_slice(&x[..self.n]);
        }
        let root = th.hash(&[&pk_tweak(epoch), &ends]);
        PublicKey { p: p.to_vec(), root: root[..self.n].to_vec() }
    }

    /// Returns (signature, number of encoding attempts).
    pub fn sign(&self, sk_seed: &[u8; 32], p: &[u8], epoch: u32, msg: &[u8; 32]) -> (Vec<u8>, u64) {
        let th = Seeded::from_seed(p);
        let mut ctr: u64 = 0;
        let (rho, chunks) = loop {
            let r = sha256(&[sk_seed, &[0x04], &epoch.to_be_bytes(), msg, &ctr.to_be_bytes()]);
            let rho = &r[..self.rho_len];
            ctr += 1;
            if let Some(c) = self.encode(p, rho, epoch, msg) {
                break (rho.to_vec(), c);
            }
            assert!(ctr < 1 << 24, "target sum never hit");
        };
        let mut sig = rho;
        for (i, &c) in chunks.iter().enumerate() {
            let mut x = self.chain_start(sk_seed, epoch, i);
            self.walk(&th, epoch, i, &mut x, 0, c);
            sig.extend_from_slice(&x[..self.n]);
        }
        (sig, ctr)
    }

    pub fn verify(&self, pk: &PublicKey, epoch: u32, msg: &[u8; 32], sig: &[u8]) -> bool {
        if sig.len() != self.sig_len() {
            return false;
        }
        let (rho, rest) = sig.split_at(self.rho_len);
        let Some(chunks) = self.encode(&pk.p, rho, epoch, msg) else {
            return false;
        };
        let th = Seeded::from_seed(&pk.p);
        let mut ends = Vec::with_capacity(self.v * self.n);
        for (i, &c) in chunks.iter().enumerate() {
            let mut x = [0u8; 32];
            x[..self.n].copy_from_slice(&rest[i * self.n..(i + 1) * self.n]);
            self.walk(&th, epoch, i, &mut x, c, self.base() - 1);
            ends.extend_from_slice(&x[..self.n]);
        }
        let root = th.hash(&[&pk_tweak(epoch), &ends]);
        root[..self.n] == pk.root[..]
    }
}

// ---------------- Small Merkle tree of K one-time keys under one P ----------------
// Leaf i is the OTS key at epoch i; node tweak = [0x05, level, index].

fn node_tweak(level: u8, idx: u32) -> [u8; 6] {
    let i = idx.to_be_bytes();
    [0x05, level, i[0], i[1], i[2], i[3]]
}

pub struct TreeKey {
    pub pk: PublicKey,
    levels: Vec<Vec<Vec<u8>>>,
}

impl Params {
    pub fn tree_sig_len(&self, h: usize) -> usize {
        1 + self.sig_len() + h * self.n
    }

    pub fn tree_keygen(&self, sk_seed: &[u8; 32], p: &[u8], h: usize) -> TreeKey {
        let th = Seeded::from_seed(p);
        let mut levels = vec![(0..1u32 << h).map(|i| self.keygen(sk_seed, p, i).root).collect::<Vec<_>>()];
        for lv in 0..h {
            let prev = &levels[lv];
            let next = (0..prev.len() / 2)
                .map(|j| th.hash(&[&node_tweak(lv as u8 + 1, j as u32), &prev[2 * j], &prev[2 * j + 1]])[..self.n].to_vec())
                .collect();
            levels.push(next);
        }
        let root = levels[h][0].clone();
        TreeKey { pk: PublicKey { p: p.to_vec(), root }, levels }
    }

    pub fn tree_sign(&self, key: &TreeKey, sk_seed: &[u8; 32], leaf: u32, msg: &[u8; 32]) -> Vec<u8> {
        let mut sig = vec![leaf as u8];
        sig.extend(self.sign(sk_seed, &key.pk.p, leaf, msg).0);
        for lv in 0..key.levels.len() - 1 {
            sig.extend_from_slice(&key.levels[lv][((leaf >> lv) ^ 1) as usize]);
        }
        sig
    }

    pub fn tree_verify(&self, pk: &PublicKey, h: usize, msg: &[u8; 32], sig: &[u8]) -> bool {
        if sig.len() != self.tree_sig_len(h) || (sig[0] as usize) >> h != 0 {
            return false;
        }
        let leaf = sig[0] as u32;
        let ots = &sig[1..1 + self.sig_len()];
        let auth = &sig[1 + self.sig_len()..];
        let (rho, rest) = ots.split_at(self.rho_len);
        let Some(chunks) = self.encode(&pk.p, rho, leaf, msg) else {
            return false;
        };
        let th = Seeded::from_seed(&pk.p);
        let mut ends = Vec::with_capacity(self.v * self.n);
        for (i, &c) in chunks.iter().enumerate() {
            let mut x = [0u8; 32];
            x[..self.n].copy_from_slice(&rest[i * self.n..(i + 1) * self.n]);
            self.walk(&th, leaf, i, &mut x, c, self.base() - 1);
            ends.extend_from_slice(&x[..self.n]);
        }
        let mut node = th.hash(&[&pk_tweak(leaf), &ends])[..self.n].to_vec();
        for lv in 0..h {
            let a = &auth[lv * self.n..(lv + 1) * self.n];
            let j = leaf >> (lv + 1);
            let t = node_tweak(lv as u8 + 1, j);
            node = if (leaf >> lv) & 1 == 0 { th.hash(&[&t, &node, a]) } else { th.hash(&[&t, a, &node]) }[..self.n].to_vec();
        }
        node == pk.root
    }
}
