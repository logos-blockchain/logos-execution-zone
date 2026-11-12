# WOTS+ tree specification

The WOTS+ tree (`tree.rs`) signs 32-byte messages with a tree of 8 WOTS+
one-time keys. Its WOTS+ keys, tree and hash functions are FIPS 205's, at the
parameters of SLH-DSA-SHA2-128f. What FIPS 205 does not define (how the tree is derived from
a seed, how a message becomes the value WOTS+ signs, and the byte layout) is
specified here.

The scheme as a whole is not SLH-DSA and is not NIST-approved; only its
components are standardized.

## Parameters

| Name | Value | Meaning |
| --- | --- | --- |
| `n` | 16 | Hash length, bytes |
| `w` | 16 (`lg_w = 4`) | Winternitz parameter |
| `len` | 35 | WOTS+ chains: 32 message chains, 3 checksum chains |
| `h'` | 3 | Tree height: 8 leaves |
| Hash functions | SHA2, Security Category 1 | FIPS 205 §11.2.1 (`F`, `H`, `T_l`, `PRF`, `PRF_msg`, `H_msg`) |

These are exactly SLH-DSA-SHA2-128f's values for `n`, `lg_w` and `h'`.

## From FIPS 205, unchanged

- The chain function, WOTS+ key generation, signing and public-key recovery
  (Algorithms 5 to 8).
- XMSS tree nodes, signing and root recovery (Algorithms 9 to 11).
- The hash functions of §11.2.1, including `PRF_msg` and `H_msg`.
- The address layout (§4.2) and its compressed form (§11.2).

The implementation is `slh-dsa`'s own code, reached through its `hazmat` feature.

## Specified here

### Key derivation

A tree is derived from a 32-byte `seed`:

```
SK.seed = SHA-256("WotsTree/v1/SK.seed" || seed)[0..16]
SK.prf  = SHA-256("WotsTree/v1/SK.prf"  || seed)[0..16]
PK.seed = SHA-256("WotsTree/v1/PK.seed" || seed)[0..16]
root    = xmss_node(SK.seed, 0, h', PK.seed, ADRS)    // Algorithm 9
```

Strings are ASCII, with no terminator. `ADRS` has layer address 0 and tree
address 0 throughout. There is only one tree, so the 8 leaves are
key-pair addresses 0 to 7 of that tree. Distinct trees are told apart by their
`PK.seed`.

`SK.seed` and `SK.prf` are secret. Publishing `PK.seed` reveals nothing about
them, since each comes from a different domain-separated hash.

The public key is `PK.seed || root` (32 bytes).

### Signing

To sign a 32-byte message `M` with leaf `i` (0 to 7):

```
R      = PRF_msg(SK.prf, PK.seed, M)                     // 16 bytes
digest = H_msg(R, PK.seed, root, M)[0..16]
sig    = xmss_sign(digest, SK.seed, i, PK.seed, ADRS)    // Algorithm 10
```

- **Deterministic `R`.** `PK.seed` is passed as `opt_rand`, as in FIPS 205's
  deterministic variant. Signing must be deterministic: in SLH-DSA, WOTS+ only
  signs tree roots and FORS keys, which are the same each time, but here it
  signs a message digest directly. A fresh `R` on a re-send would make one
  leaf sign two different digests, which breaks the one-time key.
- **Digest.** `H_msg` for SHA2 at Category 1 is MGF1-SHA-256, which produces
  its output in 32-byte blocks. The first 16 bytes of its `m`-byte output are
  therefore the same for any `m >= 16`.
- **Leaf choice** is the signer's. Each leaf must sign at most one message;
  signing the same message again with the same leaf repeats the signature
  exactly.

### Signature layout (625 bytes)

| Bytes | Field |
| --- | --- |
| 0 | Leaf index `i`, 0 to 7 |
| 1 to 16 | `R` |
| 17 to 576 | WOTS+ signature: 35 chain values of 16 bytes, chain 0 first |
| 577 to 624 | Authentication path: 3 nodes of 16 bytes, from the leaf's sibling up |

### Verification

1. **Precheck** (no hashing): the signature is exactly 625 bytes and its leaf
   index is below 8. Otherwise it is malformed.
2. Recompute `digest = H_msg(R, PK.seed, root, M)[0..16]` from the signature's `R`.
3. Recover a root with `xmss_pk_from_sig(i, sig, digest, PK.seed, ADRS)` (Algorithm 11).
4. Accept if and only if it equals `root`.

`R` is part of the signature because the verifier cannot compute it without
`SK.prf`. It makes the digest unpredictable before signing, so forging requires
a second preimage (about 2^128 work) rather than a collision (about 2^64).

## Secret handling

`SK.seed` and `SK.prf` are cleared when a tree is dropped, and so are the
intermediate copies `tree.rs` and `hazmat` make. The WOTS+ chain secrets
computed inside `slh-dsa` are not cleared; neither is SLH-DSA's own signing
path.

## Test vectors

The `tree` tests fix, for `seed = 00 01 .. 1f`, `M = ab × 32` and leaf 5, the
public key, the first 48 bytes of the signature and its SHA-256
(`fixed_seed_vectors`), and re-derive each step above directly from `hazmat`
and SHA-256 (`spec_derivation_matches`).
