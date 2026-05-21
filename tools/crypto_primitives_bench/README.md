# crypto_primitives_bench

Cryptographic primitive microbenchmarks used by client/wallet code. Single host binary, no live sequencer or Bedrock needed.

## Run

```sh
cargo run --release -p crypto_primitives_bench
```

## What you'll see

Per-operation `best_us`, `mean_us`, and `stdev_us` over 100 iterations (plus 2 warmup):

- `KeyChain::new_os_random` — full mnemonic → SSK → NSK/VSK + public-key derivation (HMAC-SHA512 PBKDF dominates).
- `KeyChain::new_mnemonic` — same pipeline, mnemonic exposed.
- `SharedSecretKey::new (sender DH)` — secp256k1 ECDH per recipient.
- `EncryptionScheme::encrypt` / `decrypt` — ChaCha20 over an Account note.

JSON output is written to `target/crypto_primitives_bench.json`.
