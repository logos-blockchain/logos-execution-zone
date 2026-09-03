# crypto_primitives_bench

Criterion-driven microbenchmarks for the cryptographic primitives client/wallet code uses on every transaction. No live sequencer or Bedrock needed.

## Run

```sh
cargo bench -p crypto_primitives_bench --bench primitives
```

## What you'll see

Criterion's per-operation report (point estimate, 95% CI, outlier counts) for:

- `keychain/new_os_random`: full derivation: seed → secret spending key → private key holder → nullifier public key and ML-KEM-768 viewing public key (the BIP39 PBKDF dominates).
- `keychain/new_mnemonic`: same pipeline, mnemonic exposed.
- `shared_secret_key/sender_encapsulate`: ML-KEM-768 encapsulation toward the recipient's viewing public key; the per-recipient cost of an outbound note.
- `encryption/encrypt` / `decrypt`: ChaCha20 over an Account note, keyed from the shared secret and the note's nullifier.

Per-bench JSON estimates are written under `target/criterion/<group>/<bench>/`. HTML reports at `target/criterion/report/index.html`.

## Baseline comparison

```sh
# On main:
cargo bench -p crypto_primitives_bench --bench primitives -- --save-baseline main
# On your branch:
cargo bench -p crypto_primitives_bench --bench primitives -- --baseline main
```
