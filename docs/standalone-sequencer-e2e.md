# Standalone-sequencer end-to-end recipe

How to run a full wallet flow — init, faucet claim, transfer — against a
self-contained chain with no external services. Useful for integration
tests and CI.

The `standalone` feature swaps the bedrock/indexer dependencies for
in-process mocks, and the `testnet` genesis ships the pinata faucet. Guest
program `.bin` artifacts are committed in the repo, so no `risc0`/docker
step is needed.

## System dependencies

`librocksdb-sys` builds bindgen bindings, so a libclang dev package is
required:

```bash
# Debian/Ubuntu
sudo apt-get install -y libclang-dev protobuf-compiler
# Fedora
sudo dnf install -y clang-devel protobuf-compiler
```

## Build and run

```bash
cargo build -p sequencer_service --features standalone --release

mkdir -p /tmp/seq-home
./target/release/sequencer_service \
    lez/sequencer/service/configs/debug/sequencer_config.json \
    --port 3040 --listen-address 127.0.0.1 --home /tmp/seq-home &
```

Wait for readiness — the pinata faucet account is funded in the testnet
genesis, so polling `getAccount` is a reliable readiness probe:

```bash
for i in $(seq 1 60); do
    curl -sf -X POST http://127.0.0.1:3040 \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getAccount",
             "params":{"account_id":"EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7"}}' \
        | grep -q '"balance":1500000' && break
    sleep 1
done
```

## Point the wallet at it

Either write a wallet config naming `http://127.0.0.1:3040` as the only
sequencer, or — if `LEZ_SEQUENCER_URL` support is present in
`lez/wallet/src/config.rs` — set it in the environment so no config file
is needed at all.

## Gotchas

- **Block time is `block_create_timeout`, not a slot interval.** In
  standalone mode blocks are produced on a ~15 s timeout, so balance and
  receipt assertions must poll — a single immediate check will race the
  block. Poll for up to ~90 s.
- **The wallet prints config notices to stdout before JSON.** Commands
  that emit a JSON result precede it with human-readable notices. Extract
  the document with `awk '/^{$/,0'` before piping to `jq`.
- **The faucet account is only funded under the `testnet` genesis.**
  Other genesis configs will not have the `1500000` balance or the
  `can_claim` faucet path.

## Minimal e2e

```bash
wallet init
ALICE=$(wallet new-account alice | awk '/^{$/,0' | jq -r .account_id)
wallet faucet-info | awk '/^{$/,0' | jq -e '.can_claim == true'
wallet faucet-claim "$ALICE" | awk '/^{$/,0' | jq -e '.balance_after'
BOB=$(wallet new-account bob | awk '/^{$/,0' | jq -r .account_id)
wallet transfer "$ALICE" --to "$BOB" 50 | awk '/^{$/,0' | jq -e .hash

# blocks land on block_create_timeout — poll
for i in $(seq 1 12); do
    BAL=$(wallet balance "$BOB" | awk '/^{$/,0' | jq -r .balance)
    [ "$BAL" = "50" ] && break
    sleep 8
done
[ "$BAL" = "50" ]
```
