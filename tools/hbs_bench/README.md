# hbs-bench

Benchmarks for hash-based signature candidates for LEE public accounts: target-sum and checksum Winternitz (one key, or a small backup tree of 4 or 8 keys per nonce), SLH-DSA (FIPS 205) leaves and small trees, XMSS (RFC 8391) leaves and small trees, the full SLH-DSA and XMSS schemes, and BIP-340 Schnorr as the baseline. Everything uses SHA-256.

This is benchmark code, not production code. The Winternitz implementations are checked for sizes, hash counts and encoding behaviour, but not against reference test vectors, and have had no security review.

The crate is standalone (its own `[workspace]`), so its pre-release dependencies stay out of the main workspace.

## Running

```sh
cargo build --release
./target/release/hbs-bench --selftest            # correctness checks: valid signatures verify, tampering is rejected
./target/release/hbs-bench --budget 300          # all one-key schemes, standard leaves and full schemes
./target/release/hbs-bench --trees --budget 300  # backup trees (K = 4, 8) for every family
./target/release/hbs-bench --trees --l1a         # backup trees at Level 1, n = 16 only
./target/release/hbs-bench --grind               # check-sum vs. target-sum verify cost over 65,536 signatures
./target/release/hbs-bench --only "L1 fresh,L1 attack"   # restrict one-key runs to parameter groups
```

Output is a Markdown table. For stable timings, pin to one core (e.g. `taskset -c 2`); the SHA-256 block counts do not depend on the machine.

## Layout

| File | Contents |
| --- | --- |
| `src/tsw.rs` | Target-sum and checksum Winternitz (target-sum paper, Constructions 5 and 6), plus backup trees |
| `src/fips205.rs` | FIPS 205 WOTS+, FORS, hypertree verification, small trees and mini SLH-DSA |
| `src/rfc8391.rs` | RFC 8391 WOTS+, L-tree, XMSS verification and small trees |
| `src/hash.rs` | SHA-256 wrappers that count compressions |
| `src/main.rs` | Parameter sets, timing harness and self-test |
| `scripts/params.py`, `scripts/l3.py` | Provable parameter sets (reimplements the bounds in b-wagn/hashsig-parameters) |
| `scripts/attack_params.py` | Attack-based (n = 16) parameter sets |
| `scripts/reuse.py`, `scripts/fors_reuse.py` | Remaining security after a key signs several messages |
| `scripts/block_all.py` | Block capacity and block verify time |

Run the scripts with `python3 -I scripts/<name>.py`; they need only the standard library.
