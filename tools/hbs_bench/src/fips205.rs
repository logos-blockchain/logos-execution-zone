//! FIPS 205 (SLH-DSA) building blocks, SHA2 "simple" instantiation.
//! Category 1 is byte-exact with the standard; for n = 32 we keep SHA-256 everywhere
//! (FIPS 205 would use SHA-512 for H, T_l and H_msg at categories 3/5).

use crate::hash::{Seeded, sha256};

const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub name: &'static str,
    pub n: usize,
    pub h: usize,
    pub d: usize,
    pub hp: usize,
    pub a: usize,
    pub k: usize,
    pub m: usize,
}

pub const SHA2_128S: Params = Params { name: "128s", n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, m: 30 };
pub const SHA2_128F: Params = Params { name: "128f", n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, m: 34 };
pub const SHA2_256S: Params = Params { name: "256s", n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, m: 47 };
pub const SHA2_256F: Params = Params { name: "256f", n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, m: 49 };

const LGW: usize = 4;
const W: u32 = 16;
const LEN2: usize = 3;

impl Params {
    pub fn len1(&self) -> usize {
        2 * self.n
    }
    pub fn len(&self) -> usize {
        self.len1() + LEN2
    }
    pub fn wots_sig_len(&self) -> usize {
        self.len() * self.n
    }
    pub fn fors_sig_len(&self) -> usize {
        self.k * (self.a + 1) * self.n
    }
    pub fn md_len(&self) -> usize {
        (self.k * self.a).div_ceil(8)
    }
}

#[derive(Clone, Copy, Default)]
pub struct Adrs([u8; 32]);

impl Adrs {
    fn set_word(&mut self, i: usize, v: u32) {
        self.0[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    fn word(&self, i: usize) -> u32 {
        u32::from_be_bytes(self.0[i * 4..i * 4 + 4].try_into().unwrap())
    }
    pub fn set_layer(&mut self, l: u32) {
        self.set_word(0, l);
    }
    pub fn set_tree(&mut self, t: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&t.to_be_bytes());
    }
    pub fn set_type_and_clear(&mut self, t: u32) {
        self.set_word(4, t);
        self.0[20..32].fill(0);
    }
    pub fn set_keypair(&mut self, v: u32) {
        self.set_word(5, v);
    }
    pub fn keypair(&self) -> u32 {
        self.word(5)
    }
    fn set_chain(&mut self, v: u32) {
        self.set_word(6, v);
    }
    fn set_tree_height(&mut self, v: u32) {
        self.set_word(6, v);
    }
    fn set_hash(&mut self, v: u32) {
        self.set_word(7, v);
    }
    fn set_tree_index(&mut self, v: u32) {
        self.set_word(7, v);
    }
    fn tree_index(&self) -> u32 {
        self.word(7)
    }
    fn compressed(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        c[0] = self.0[3];
        c[1..9].copy_from_slice(&self.0[8..16]);
        c[9] = self.0[19];
        c[10..22].copy_from_slice(&self.0[20..32]);
        c
    }
}

pub struct Ctx {
    pub p: Params,
    pub pk_seed: Vec<u8>,
    th: Seeded,
}

fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let (mut idx, mut bits, mut total) = (0usize, 0usize, 0u64);
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | x[idx] as u64;
            idx += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) & ((1 << b) - 1)) as u32);
        total &= (1 << bits) - 1;
    }
    out
}

fn to_int(x: &[u8]) -> u64 {
    x.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)
}

impl Ctx {
    pub fn new(p: Params, pk_seed: &[u8]) -> Self {
        assert_eq!(pk_seed.len(), p.n);
        Self { p, pk_seed: pk_seed.to_vec(), th: Seeded::from_seed(pk_seed) }
    }

    fn th(&self, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
        self.th.hash(&[&adrs.compressed(), m])[..self.p.n].to_vec()
    }

    fn th_into(&self, adrs: &Adrs, m: &[u8], out: &mut [u8]) {
        let h = self.th.hash(&[&adrs.compressed(), m]);
        out.copy_from_slice(&h[..self.p.n]);
    }

    fn prf(&self, adrs: &Adrs, sk_seed: &[u8]) -> Vec<u8> {
        self.th(adrs, sk_seed)
    }

    /// H_msg for SHA2 category 1: MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m).
    pub fn h_msg(&self, r: &[u8], pk_root: &[u8], msg: &[u8], out_len: usize) -> Vec<u8> {
        let inner = sha256(&[r, &self.pk_seed, pk_root, msg]);
        let mut out = Vec::with_capacity(out_len + 32);
        let mut ctr: u32 = 0;
        while out.len() < out_len {
            out.extend_from_slice(&sha256(&[r, &self.pk_seed, &inner, &ctr.to_be_bytes()]));
            ctr += 1;
        }
        out.truncate(out_len);
        out
    }

    // ---------------- WOTS+ ----------------

    fn wots_digits(&self, m: &[u8]) -> Vec<u32> {
        let mut d = base_2b(m, LGW, self.p.len1());
        let mut csum: u32 = d.iter().map(|x| W - 1 - x).sum();
        csum <<= (8 - ((LEN2 * LGW) % 8)) % 8;
        let cb = csum.to_be_bytes();
        let nbytes = (LEN2 * LGW).div_ceil(8);
        d.extend(base_2b(&cb[4 - nbytes..], LGW, LEN2));
        d
    }

    fn chain(&self, x: &mut [u8], i: u32, s: u32, adrs: &mut Adrs) {
        for j in i..i + s {
            adrs.set_hash(j);
            let h = self.th.hash(&[&adrs.compressed(), x]);
            x.copy_from_slice(&h[..self.p.n]);
        }
    }

    fn wots_sk(&self, sk_seed: &[u8], adrs: &Adrs, i: u32) -> Vec<u8> {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(WOTS_PRF);
        sk_adrs.set_keypair(adrs.keypair());
        sk_adrs.set_chain(i);
        self.prf(&sk_adrs, sk_seed)
    }

    fn wots_pk_compress(&self, adrs: &Adrs, tmp: &[u8]) -> Vec<u8> {
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_keypair(adrs.keypair());
        self.th(&pk_adrs, tmp)
    }

    pub fn wots_keygen(&self, sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
        let n = self.p.n;
        let mut a = *adrs;
        let mut tmp = vec![0u8; self.p.len() * n];
        for i in 0..self.p.len() {
            let x = &mut tmp[i * n..(i + 1) * n];
            x.copy_from_slice(&self.wots_sk(sk_seed, adrs, i as u32));
            a.set_chain(i as u32);
            self.chain(x, 0, W - 1, &mut a);
        }
        self.wots_pk_compress(adrs, &tmp)
    }

    pub fn wots_sign(&self, m: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
        let n = self.p.n;
        let d = self.wots_digits(m);
        let mut a = *adrs;
        let mut sig = vec![0u8; self.p.len() * n];
        for i in 0..self.p.len() {
            let x = &mut sig[i * n..(i + 1) * n];
            x.copy_from_slice(&self.wots_sk(sk_seed, adrs, i as u32));
            a.set_chain(i as u32);
            self.chain(x, 0, d[i], &mut a);
        }
        sig
    }

    pub fn wots_pk_from_sig(&self, sig: &[u8], m: &[u8], adrs: &Adrs) -> Vec<u8> {
        let n = self.p.n;
        let d = self.wots_digits(m);
        let mut a = *adrs;
        let mut tmp = sig.to_vec();
        for i in 0..self.p.len() {
            a.set_chain(i as u32);
            self.chain(&mut tmp[i * n..(i + 1) * n], d[i], W - 1 - d[i], &mut a);
        }
        self.wots_pk_compress(adrs, &tmp)
    }

    // ---------------- FORS ----------------

    /// All levels of FORS tree `t`: levels[z][j] is node j at height z (n bytes each).
    fn fors_tree_levels(&self, sk_seed: &[u8], adrs: &Adrs, t: usize) -> Vec<Vec<u8>> {
        let (n, a) = (self.p.n, self.p.a);
        let mut levels = Vec::with_capacity(a + 1);
        let mut leaves = vec![0u8; (1 << a) * n];
        let mut fa = *adrs;
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_keypair(adrs.keypair());
        for j in 0..1usize << a {
            let idx = (t << a) + j;
            sk_adrs.set_tree_index(idx as u32);
            let sk = self.prf(&sk_adrs, sk_seed);
            fa.set_tree_height(0);
            fa.set_tree_index(idx as u32);
            self.th_into(&fa, &sk, &mut leaves[j * n..(j + 1) * n]);
        }
        levels.push(leaves);
        for z in 1..=a {
            let prev = &levels[z - 1];
            let cnt = 1usize << (a - z);
            let mut cur = vec![0u8; cnt * n];
            for j in 0..cnt {
                fa.set_tree_height(z as u32);
                fa.set_tree_index(((t << (a - z)) + j) as u32);
                self.th_into(&fa, &prev[2 * j * n..(2 * j + 2) * n], &mut cur[j * n..(j + 1) * n]);
            }
            levels.push(cur);
        }
        levels
    }

    fn fors_roots_compress(&self, adrs: &Adrs, roots: &[u8]) -> Vec<u8> {
        let mut ra = *adrs;
        ra.set_type_and_clear(FORS_ROOTS);
        ra.set_keypair(adrs.keypair());
        self.th(&ra, roots)
    }

    pub fn fors_keygen(&self, sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
        let mut roots = Vec::with_capacity(self.p.k * self.p.n);
        for t in 0..self.p.k {
            let lv = self.fors_tree_levels(sk_seed, adrs, t);
            roots.extend_from_slice(&lv[self.p.a]);
        }
        self.fors_roots_compress(adrs, &roots)
    }

    pub fn fors_sign(&self, md: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
        let (n, a) = (self.p.n, self.p.a);
        let idx = base_2b(md, a, self.p.k);
        let mut sig = Vec::with_capacity(self.p.fors_sig_len());
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_keypair(adrs.keypair());
        for t in 0..self.p.k {
            let leaf = idx[t] as usize;
            sk_adrs.set_tree_index(((t << a) + leaf) as u32);
            sig.extend_from_slice(&self.prf(&sk_adrs, sk_seed));
            let lv = self.fors_tree_levels(sk_seed, adrs, t);
            for j in 0..a {
                let s = (leaf >> j) ^ 1;
                sig.extend_from_slice(&lv[j][s * n..(s + 1) * n]);
            }
        }
        sig
    }

    pub fn fors_pk_from_sig(&self, sig: &[u8], md: &[u8], adrs: &Adrs) -> Vec<u8> {
        let (n, a) = (self.p.n, self.p.a);
        let idx = base_2b(md, a, self.p.k);
        let mut roots = Vec::with_capacity(self.p.k * n);
        let mut fa = *adrs;
        let mut buf = vec![0u8; 2 * n];
        for t in 0..self.p.k {
            let part = &sig[t * (a + 1) * n..(t + 1) * (a + 1) * n];
            fa.set_tree_height(0);
            fa.set_tree_index(((t << a) as u32) + idx[t]);
            let mut node = self.th(&fa, &part[..n]);
            for j in 0..a {
                let auth = &part[(j + 1) * n..(j + 2) * n];
                fa.set_tree_height(j as u32 + 1);
                if (idx[t] >> j) & 1 == 0 {
                    fa.set_tree_index(fa.tree_index() / 2);
                    buf[..n].copy_from_slice(&node);
                    buf[n..].copy_from_slice(auth);
                } else {
                    fa.set_tree_index((fa.tree_index() - 1) / 2);
                    buf[..n].copy_from_slice(auth);
                    buf[n..].copy_from_slice(&node);
                }
                node = self.th(&fa, &buf);
            }
            roots.extend_from_slice(&node);
        }
        self.fors_roots_compress(adrs, &roots)
    }

    // ---------------- Hypertree (verification only; used to cross-check against slh-dsa) ----------------

    fn xmss_pk_from_sig(&self, idx: u32, sig: &[u8], m: &[u8], adrs: &mut Adrs) -> Vec<u8> {
        let n = self.p.n;
        let ws = self.p.wots_sig_len();
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_keypair(idx);
        let mut node = self.wots_pk_from_sig(&sig[..ws], m, adrs);
        adrs.set_type_and_clear(TREE);
        adrs.set_tree_index(idx);
        let mut buf = vec![0u8; 2 * n];
        for k in 0..self.p.hp {
            let auth = &sig[ws + k * n..ws + (k + 1) * n];
            adrs.set_tree_height(k as u32 + 1);
            if (idx >> k) & 1 == 0 {
                adrs.set_tree_index(adrs.tree_index() / 2);
                buf[..n].copy_from_slice(&node);
                buf[n..].copy_from_slice(auth);
            } else {
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                buf[..n].copy_from_slice(auth);
                buf[n..].copy_from_slice(&node);
            }
            node = self.th(adrs, &buf);
        }
        node
    }

    /// Full `slh_verify_internal` (FIPS 205 Alg. 20).
    pub fn slh_verify(&self, pk_root: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let p = self.p;
        let n = p.n;
        let xs = p.wots_sig_len() + p.hp * n;
        if sig.len() != n + p.fors_sig_len() + p.d * xs {
            return false;
        }
        let r = &sig[..n];
        let fors_sig = &sig[n..n + p.fors_sig_len()];
        let ht_sig = &sig[n + p.fors_sig_len()..];
        let digest = self.h_msg(r, pk_root, msg, p.m);
        let md = &digest[..p.md_len()];
        let tl = (p.h - p.hp).div_ceil(8);
        let ll = p.hp.div_ceil(8);
        let mut idx_tree = to_int(&digest[p.md_len()..p.md_len() + tl]);
        if p.h - p.hp < 64 {
            idx_tree &= (1u64 << (p.h - p.hp)) - 1;
        }
        let mut idx_leaf = (to_int(&digest[p.md_len() + tl..p.md_len() + tl + ll]) & ((1 << p.hp) - 1)) as u32;

        let mut adrs = Adrs::default();
        adrs.set_tree(idx_tree);
        adrs.set_type_and_clear(FORS_TREE);
        adrs.set_keypair(idx_leaf);
        let mut node = self.fors_pk_from_sig(fors_sig, md, &adrs);

        let mut adrs = Adrs::default();
        adrs.set_tree(idx_tree);
        node = self.xmss_pk_from_sig(idx_leaf, &ht_sig[..xs], &node, &mut adrs);
        for j in 1..p.d {
            idx_leaf = (idx_tree & ((1 << p.hp) - 1)) as u32;
            idx_tree >>= p.hp;
            let mut adrs = Adrs::default();
            adrs.set_layer(j as u32);
            adrs.set_tree(idx_tree);
            node = self.xmss_pk_from_sig(idx_leaf, &ht_sig[j * xs..(j + 1) * xs], &node, &mut adrs);
        }
        node == pk_root
    }
}

// ---------------- One-time leaf schemes: a single WOTS+ or FORS key stored in the account ----------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Leaf {
    Wots,
    Fors,
}

pub struct LeafKey {
    pub ctx: Ctx,
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub adrs: Adrs,
    pub pk: Vec<u8>,
}

pub fn leaf_adrs(kind: Leaf, epoch: u64) -> Adrs {
    let mut a = Adrs::default();
    a.set_tree(epoch);
    a.set_type_and_clear(if kind == Leaf::Wots { WOTS_HASH } else { FORS_TREE });
    a
}

impl Params {
    pub fn leaf_sig_len(&self, kind: Leaf) -> usize {
        self.n + if kind == Leaf::Wots { self.wots_sig_len() } else { self.fors_sig_len() }
    }
}

pub fn leaf_keygen(p: Params, kind: Leaf, seed: &[u8; 32], epoch: u64) -> LeafKey {
    let s = sha256(&[seed, b"leaf-seeds"]);
    let s2 = sha256(&[seed, b"leaf-prf"]);
    let ctx = Ctx::new(p, &s[..p.n]);
    let sk_seed = s2[..p.n].to_vec();
    let sk_prf = s[32 - p.n..].to_vec();
    let adrs = leaf_adrs(kind, epoch);
    let pk = match kind {
        Leaf::Wots => ctx.wots_keygen(&sk_seed, &adrs),
        Leaf::Fors => ctx.fors_keygen(&sk_seed, &adrs),
    };
    LeafKey { ctx, sk_seed, sk_prf, adrs, pk }
}

fn leaf_digest(ctx: &Ctx, kind: Leaf, r: &[u8], pk: &[u8], msg: &[u8]) -> Vec<u8> {
    let len = if kind == Leaf::Wots { ctx.p.n } else { ctx.p.md_len() };
    ctx.h_msg(r, pk, msg, len)
}

pub fn leaf_sign(key: &LeafKey, kind: Leaf, msg: &[u8]) -> Vec<u8> {
    let ctx = &key.ctx;
    let r = sha256(&[&key.sk_prf, msg])[..ctx.p.n].to_vec();
    let d = leaf_digest(ctx, kind, &r, &key.pk, msg);
    let mut sig = r;
    sig.extend(match kind {
        Leaf::Wots => ctx.wots_sign(&d, &key.sk_seed, &key.adrs),
        Leaf::Fors => ctx.fors_sign(&d, &key.sk_seed, &key.adrs),
    });
    sig
}

/// Verifier-side: only needs (PK.seed, leaf pk, epoch).
pub fn leaf_verify(ctx: &Ctx, kind: Leaf, pk: &[u8], epoch: u64, msg: &[u8], sig: &[u8]) -> bool {
    let n = ctx.p.n;
    if sig.len() != ctx.p.leaf_sig_len(kind) {
        return false;
    }
    let (r, body) = sig.split_at(n);
    let d = leaf_digest(ctx, kind, r, pk, msg);
    let adrs = leaf_adrs(kind, epoch);
    let got = match kind {
        Leaf::Wots => ctx.wots_pk_from_sig(body, &d, &adrs),
        Leaf::Fors => ctx.fors_pk_from_sig(body, &d, &adrs),
    };
    got == pk
}

// ---------------- Small trees (one XMSS layer of height hp, d = 1) ----------------

pub struct TreeKey {
    pub ctx: Ctx,
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub root: Vec<u8>,
    levels: Vec<Vec<Vec<u8>>>,
}

/// `p.hp` is the tree height; `p.h` must equal `p.hp` and `p.d` must be 1.
pub fn tree_keygen(p: Params, seed: &[u8; 32]) -> TreeKey {
    assert!(p.d == 1 && p.h == p.hp);
    let s = sha256(&[seed, b"tree-seeds"]);
    let s2 = sha256(&[seed, b"tree-prf"]);
    let ctx = Ctx::new(p, &s[..p.n]);
    let sk_seed = s2[..p.n].to_vec();
    let sk_prf = s[32 - p.n..].to_vec();
    let mut wa = Adrs::default();
    wa.set_type_and_clear(WOTS_HASH);
    let mut levels = vec![(0..1u32 << p.hp)
        .map(|i| {
            wa.set_keypair(i);
            ctx.wots_keygen(&sk_seed, &wa)
        })
        .collect::<Vec<_>>()];
    let mut ta = Adrs::default();
    ta.set_type_and_clear(TREE);
    for z in 1..=p.hp {
        let prev = &levels[z - 1];
        let next = (0..prev.len() / 2)
            .map(|j| {
                ta.set_tree_height(z as u32);
                ta.set_tree_index(j as u32);
                ctx.th(&ta, &[prev[2 * j].as_slice(), prev[2 * j + 1].as_slice()].concat())
            })
            .collect();
        levels.push(next);
    }
    let root = levels[p.hp][0].clone();
    TreeKey { ctx, sk_seed, sk_prf, root, levels }
}

impl TreeKey {
    fn auth(&self, idx: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for z in 0..self.ctx.p.hp {
            out.extend_from_slice(&self.levels[z][((idx >> z) ^ 1) as usize]);
        }
        out
    }
}

impl Params {
    /// Stateful WOTS+ tree: idx(1) || r || wots || auth.
    pub fn wots_tree_sig_len(&self) -> usize {
        1 + self.n + self.wots_sig_len() + self.hp * self.n
    }
    /// Stateless d = 1 SLH-DSA: r || fors || wots || auth.
    pub fn mini_slh_sig_len(&self) -> usize {
        self.n + self.fors_sig_len() + self.wots_sig_len() + self.hp * self.n
    }
}

pub fn wots_tree_sign(key: &TreeKey, idx: u32, msg: &[u8]) -> Vec<u8> {
    let ctx = &key.ctx;
    let r = sha256(&[&key.sk_prf, &idx.to_be_bytes(), msg])[..ctx.p.n].to_vec();
    let d = ctx.h_msg(&r, &key.root, &[&[idx as u8][..], msg].concat(), ctx.p.n);
    let mut wa = Adrs::default();
    wa.set_type_and_clear(WOTS_HASH);
    wa.set_keypair(idx);
    let mut sig = vec![idx as u8];
    sig.extend(&r);
    sig.extend(ctx.wots_sign(&d, &key.sk_seed, &wa));
    sig.extend(key.auth(idx));
    sig
}

pub fn wots_tree_verify(ctx: &Ctx, root: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let n = ctx.p.n;
    if sig.len() != ctx.p.wots_tree_sig_len() || (sig[0] as usize) >> ctx.p.hp != 0 {
        return false;
    }
    let idx = sig[0] as u32;
    let r = &sig[1..1 + n];
    let d = ctx.h_msg(r, root, &[&[idx as u8][..], msg].concat(), n);
    let mut adrs = Adrs::default();
    ctx.xmss_pk_from_sig(idx, &sig[1 + n..], &d, &mut adrs) == root
}

/// FIPS 205 Alg. 19 with d = 1 (leaf picked by H_msg).
pub fn mini_slh_sign(key: &TreeKey, msg: &[u8]) -> Vec<u8> {
    let ctx = &key.ctx;
    let p = ctx.p;
    let r = sha256(&[&key.sk_prf, msg])[..p.n].to_vec();
    let digest = ctx.h_msg(&r, &key.root, msg, p.m);
    let md = &digest[..p.md_len()];
    let idx = (to_int(&digest[p.md_len()..p.md_len() + p.hp.div_ceil(8)]) & ((1 << p.hp) - 1)) as u32;
    let mut fa = Adrs::default();
    fa.set_type_and_clear(FORS_TREE);
    fa.set_keypair(idx);
    let fors_sig = ctx.fors_sign(md, &key.sk_seed, &fa);
    let fors_pk = ctx.fors_pk_from_sig(&fors_sig, md, &fa);
    let mut wa = Adrs::default();
    wa.set_type_and_clear(WOTS_HASH);
    wa.set_keypair(idx);
    let mut sig = r;
    sig.extend(fors_sig);
    sig.extend(ctx.wots_sign(&fors_pk, &key.sk_seed, &wa));
    sig.extend(key.auth(idx));
    sig
}
