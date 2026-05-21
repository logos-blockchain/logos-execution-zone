# crypto_primitives_bench

Criterion-driven microbenchmarks for the cryptographic primitives client/wallet code uses on every transaction. No live sequencer or Bedrock needed.

## Run

```sh
cargo bench -p crypto_primitives_bench --bench primitives
```

## What you'll see

Criterion's per-operation report (point estimate, 95% CI, outlier counts) for:

- `keychain/new_os_random`: full mnemonic → SSK → NSK/VSK + public-key derivation (HMAC-SHA512 PBKDF dominates).
- `keychain/new_mnemonic`: same pipeline, mnemonic exposed.
- `shared_secret_key/sender_dh`: secp256k1 ECDH per recipient (includes ephemeral key gen).
- `encryption/encrypt` / `decrypt`: ChaCha20 over an Account note.

Per-bench JSON estimates are written under `target/criterion/<group>/<bench>/`. HTML reports at `target/criterion/report/index.html`.

## Baseline comparison

```sh
# On main:
cargo bench -p crypto_primitives_bench --bench primitives -- --save-baseline main
# On your branch:
cargo bench -p crypto_primitives_bench --bench primitives -- --baseline main
```
