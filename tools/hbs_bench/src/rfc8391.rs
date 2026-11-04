//! RFC 8391 / SP 800-208 XMSS building blocks (SHA-256 family, w = 16).
//! Hash calls follow the reference implementation: every F/H uses a PRF-derived key and bitmask(s).

use crate::hash::{Seeded, sha256};

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub name: &'static str,
    pub n: usize,
    pub pad: usize,
    pub h: usize,
}

/// XMSS-SHA2_10_256 (RFC 8391).
pub const SHA2_256: Params = Params { name: "SHA2_256 (n=32)", n: 32, pad: 32, h: 10 };
/// XMSS-SHA2_10_192 (SP 800-208).
pub const SHA2_192: Params = Params { name: "SHA2_192 (n=24)", n: 24, pad: 4, h: 10 };

const W: u32 = 16;
const LEN2: usize = 3;

impl Params {
    pub fn len1(&self) -> usize {
        2 * self.n
    }
    pub fn len(&self) -> usize {
        self.len1() + LEN2
    }
    /// One-time leaf signature: r || WOTS sig.
    pub fn leaf_sig_len(&self) -> usize {
        self.n + self.len() * self.n
    }
}

#[derive(Clone, Copy, Default)]
pub struct Adrs([u32; 8]);

impl Adrs {
    fn bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, w) in self.0.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        b
    }
    fn with_type(base: &Adrs, t: u32) -> Adrs {
        let mut a = Adrs::default();
        a.0[0] = base.0[0];
        a.0[1] = base.0[1];
        a.0[2] = base.0[2];
        a.0[3] = t;
        a
    }
}

pub struct Ctx {
    pub p: Params,
    pub seed: Vec<u8>,
    prf_mid: Option<Seeded>,
}

fn to_bytes(x: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    let b = x.to_be_bytes();
    let k = len.min(8);
    v[len - k..].copy_from_slice(&b[8 - k..]);
    v
}

fn base_w(x: &[u8], out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    for b in x {
        out.push((*b >> 4) as u32);
        out.push((*b & 15) as u32);
    }
    out.truncate(out_len);
    out
}

impl Ctx {
    pub fn new(p: Params, seed: &[u8]) -> Self {
        let prefix = [to_bytes(3, p.pad), seed.to_vec()].concat();
        let prf_mid = (prefix.len() == 64).then(|| Seeded::new(&prefix));
        Self { p, seed: seed.to_vec(), prf_mid }
    }

    fn prf(&self, adrs: &Adrs) -> Vec<u8> {
        let a = adrs.bytes();
        let h = match &self.prf_mid {
            Some(m) => m.hash(&[&a]),
            None => sha256(&[&to_bytes(3, self.p.pad), &self.seed, &a]),
        };
        h[..self.p.n].to_vec()
    }

    fn f(&self, adrs: &mut Adrs, x: &[u8]) -> Vec<u8> {
        adrs.0[7] = 0;
        let key = self.prf(adrs);
        adrs.0[7] = 1;
        let bm = self.prf(adrs);
        let m: Vec<u8> = x.iter().zip(&bm).map(|(a, b)| a ^ b).collect();
        sha256(&[&to_bytes(0, self.p.pad), &key, &m])[..self.p.n].to_vec()
    }

    pub fn rand_hash_pub(&self, adrs: &mut Adrs, l: &[u8], r: &[u8]) -> Vec<u8> {
        self.rand_hash(adrs, l, r)
    }

    fn rand_hash(&self, adrs: &mut Adrs, l: &[u8], r: &[u8]) -> Vec<u8> {
        adrs.0[7] = 0;
        let key = self.prf(adrs);
        adrs.0[7] = 1;
        let bm0 = self.prf(adrs);
        adrs.0[7] = 2;
        let bm1 = self.prf(adrs);
        let ml: Vec<u8> = l.iter().zip(&bm0).map(|(a, b)| a ^ b).collect();
        let mr: Vec<u8> = r.iter().zip(&bm1).map(|(a, b)| a ^ b).collect();
        sha256(&[&to_bytes(1, self.p.pad), &key, &ml, &mr])[..self.p.n].to_vec()
    }

    pub fn h_msg(&self, r: &[u8], root: &[u8], idx: u64, msg: &[u8]) -> Vec<u8> {
        sha256(&[&to_bytes(2, self.p.pad), r, root, &to_bytes(idx, self.p.n), msg])[..self.p.n].to_vec()
    }

    fn digits(&self, m: &[u8]) -> Vec<u32> {
        let mut d = base_w(m, self.p.len1());
        let csum: u32 = d.iter().map(|x| W - 1 - x).sum::<u32>() << 4;
        d.extend(base_w(&csum.to_be_bytes()[2..], LEN2));
        d
    }

    fn chain(&self, x: &[u8], start: u32, steps: u32, adrs: &mut Adrs) -> Vec<u8> {
        let mut t = x.to_vec();
        for j in start..start + steps {
            adrs.0[6] = j;
            t = self.f(adrs, &t);
        }
        t
    }

    fn wots_sk(&self, sk_seed: &[u8], ots: &Adrs, i: u32) -> Vec<u8> {
        let mut a = *ots;
        a.0[5] = i;
        a.0[6] = 0;
        a.0[7] = 0;
        sha256(&[&to_bytes(4, self.p.pad), sk_seed, &self.seed, &a.bytes()])[..self.p.n].to_vec()
    }

    fn ltree(&self, mut pk: Vec<Vec<u8>>, base: &Adrs, idx: u32) -> Vec<u8> {
        let mut a = Adrs::with_type(base, 1);
        a.0[4] = idx;
        let mut len = pk.len();
        let mut height = 0;
        while len > 1 {
            a.0[5] = height;
            for i in 0..len / 2 {
                a.0[6] = i as u32;
                pk[i] = self.rand_hash(&mut a, &pk[2 * i], &pk[2 * i + 1]);
            }
            if len % 2 == 1 {
                pk[len / 2] = pk[len - 1].clone();
            }
            len = len.div_ceil(2);
            height += 1;
        }
        pk.swap_remove(0)
    }

    /// Leaf = L-tree(WOTS public key) for OTS index `idx`.
    pub fn leaf_keygen(&self, sk_seed: &[u8], base: &Adrs, idx: u32) -> Vec<u8> {
        let mut ots = Adrs::with_type(base, 0);
        ots.0[4] = idx;
        let pk: Vec<Vec<u8>> = (0..self.p.len())
            .map(|i| {
                let sk = self.wots_sk(sk_seed, &ots, i as u32);
                let mut a = ots;
                a.0[5] = i as u32;
                self.chain(&sk, 0, W - 1, &mut a)
            })
            .collect();
        self.ltree(pk, base, idx)
    }

    pub fn wots_sign(&self, m: &[u8], sk_seed: &[u8], base: &Adrs, idx: u32) -> Vec<u8> {
        let mut ots = Adrs::with_type(base, 0);
        ots.0[4] = idx;
        let d = self.digits(m);
        let mut sig = Vec::with_capacity(self.p.len() * self.p.n);
        for i in 0..self.p.len() {
            let sk = self.wots_sk(sk_seed, &ots, i as u32);
            let mut a = ots;
            a.0[5] = i as u32;
            sig.extend(self.chain(&sk, 0, d[i], &mut a));
        }
        sig
    }

    pub fn leaf_from_sig(&self, sig: &[u8], m: &[u8], base: &Adrs, idx: u32) -> Vec<u8> {
        let n = self.p.n;
        let mut ots = Adrs::with_type(base, 0);
        ots.0[4] = idx;
        let d = self.digits(m);
        let pk: Vec<Vec<u8>> = (0..self.p.len())
            .map(|i| {
                let mut a = ots;
                a.0[5] = i as u32;
                self.chain(&sig[i * n..(i + 1) * n], d[i], W - 1 - d[i], &mut a)
            })
            .collect();
        self.ltree(pk, base, idx)
    }

    /// Full single-tree XMSS verify of a detached signature `idx(4) || r || wots || auth`.
    pub fn xmss_verify(&self, root: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let (n, h) = (self.p.n, self.p.h);
        if sig.len() != 4 + n + self.p.len() * n + h * n {
            return false;
        }
        let idx = u32::from_be_bytes(sig[..4].try_into().unwrap());
        let r = &sig[4..4 + n];
        let ws = &sig[4 + n..4 + n + self.p.len() * n];
        let auth = &sig[4 + n + self.p.len() * n..];
        let m = self.h_msg(r, root, idx as u64, msg);
        let base = Adrs::default();
        let mut node = self.leaf_from_sig(ws, &m, &base, idx);
        let mut a = Adrs::with_type(&base, 2);
        for k in 0..h {
            a.0[5] = k as u32;
            a.0[6] = idx >> (k + 1);
            let au = &auth[k * n..(k + 1) * n];
            node = if (idx >> k) & 1 == 0 { self.rand_hash(&mut a, &node, au) } else { self.rand_hash(&mut a, au, &node) };
        }
        node == root
    }
}

// ---------------- One-time leaf scheme ----------------

pub struct LeafKey {
    pub ctx: Ctx,
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub leaf: Vec<u8>,
    pub idx: u32,
}

pub fn leaf_keygen(p: Params, seed: &[u8; 32], idx: u32) -> LeafKey {
    let s = sha256(&[seed, b"xmss-pub"]);
    let s2 = sha256(&[seed, b"xmss-sk"]);
    let ctx = Ctx::new(p, &s[..p.n]);
    let sk_seed = s2[..p.n].to_vec();
    let sk_prf = s2[32 - p.n..].to_vec();
    let leaf = ctx.leaf_keygen(&sk_seed, &Adrs::default(), idx);
    LeafKey { ctx, sk_seed, sk_prf, leaf, idx }
}

pub fn leaf_sign(key: &LeafKey, msg: &[u8]) -> Vec<u8> {
    let ctx = &key.ctx;
    let r = sha256(&[&key.sk_prf, msg])[..ctx.p.n].to_vec();
    let m = ctx.h_msg(&r, &key.leaf, key.idx as u64, msg);
    let mut sig = r;
    sig.extend(ctx.wots_sign(&m, &key.sk_seed, &Adrs::default(), key.idx));
    sig
}

pub fn leaf_verify(ctx: &Ctx, leaf: &[u8], idx: u32, msg: &[u8], sig: &[u8]) -> bool {
    let n = ctx.p.n;
    if sig.len() != ctx.p.leaf_sig_len() {
        return false;
    }
    let m = ctx.h_msg(&sig[..n], leaf, idx as u64, msg);
    ctx.leaf_from_sig(&sig[n..], &m, &Adrs::default(), idx) == leaf
}

// ---------------- Small XMSS tree (h = 2 or 3) ----------------

pub struct TreeKey {
    pub ctx: Ctx,
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub root: Vec<u8>,
    levels: Vec<Vec<Vec<u8>>>,
}

pub fn tree_keygen(p: Params, seed: &[u8; 32]) -> TreeKey {
    let s = sha256(&[seed, b"xmss-pub"]);
    let s2 = sha256(&[seed, b"xmss-sk"]);
    let ctx = Ctx::new(p, &s[..p.n]);
    let sk_seed = s2[..p.n].to_vec();
    let sk_prf = s2[32 - p.n..].to_vec();
    let base = Adrs::default();
    let mut levels = vec![(0..1u32 << p.h).map(|i| ctx.leaf_keygen(&sk_seed, &base, i)).collect::<Vec<_>>()];
    let mut a = Adrs::with_type(&base, 2);
    for k in 0..p.h {
        a.0[5] = k as u32;
        let prev = &levels[k];
        let next = (0..prev.len() / 2)
            .map(|j| {
                a.0[6] = j as u32;
                ctx.rand_hash_pub(&mut a, &prev[2 * j], &prev[2 * j + 1])
            })
            .collect();
        levels.push(next);
    }
    let root = levels[p.h][0].clone();
    TreeKey { ctx, sk_seed, sk_prf, root, levels }
}

/// RFC 8391 layout: idx(4) || r || wots || auth.
pub fn tree_sign(key: &TreeKey, idx: u32, msg: &[u8]) -> Vec<u8> {
    let ctx = &key.ctx;
    let r = sha256(&[&key.sk_prf, &idx.to_be_bytes(), msg])[..ctx.p.n].to_vec();
    let m = ctx.h_msg(&r, &key.root, idx as u64, msg);
    let mut sig = idx.to_be_bytes().to_vec();
    sig.extend(&r);
    sig.extend(ctx.wots_sign(&m, &key.sk_seed, &Adrs::default(), idx));
    for k in 0..ctx.p.h {
        sig.extend_from_slice(&key.levels[k][((idx >> k) ^ 1) as usize]);
    }
    sig
}
