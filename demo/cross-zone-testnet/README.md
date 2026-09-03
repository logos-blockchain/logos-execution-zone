# Cross-zone bridge demo, native on Apple Silicon

Two LEZ zones bridge a wrapped token over a shared Bedrock L1, all running as
native processes on the Mac (no Docker, no emulation). A holder locks a balance on
zone A; zone A's block carries the emission to the Bedrock; zone B's watcher reads
it, verifies it, and mints the wrapped token to the recipient. A second run shows
zone B refusing the crossing when its route is not authorized.

Everything runs native arm64: the LEZ zones/tool build with cargo, and the Bedrock
node is built from source (the amd64 Docker image hangs under emulation on Apple
Silicon, which is why we build it natively).

## What is real, what is not

Real: two independent zone deployments (separate sequencer + indexer processes),
real channels created on a real Bedrock L1 node, the cross-zone watcher and the
indexer-side verification, the full lock-then-mint mechanism, conservation of
value across the crossing.

Not real: the Bedrock is a local single-node chain we run (not a shared testnet),
proving is dev-mode (fast), and zone A's lockable balance is seeded at genesis
(a live L1 deposit lands in a vault account the lock cannot spend in this release).

## Prerequisites (one time)

    xcode-select --install      # clang/libclang for RocksDB
    brew install cmake
    # Rust is pinned per repo toolchain files; rustup handles it.

## Build (one time, heavy)

From the worktree root:

    cd ~/logos/lez-demo-v024
    CARGO_TARGET_DIR=.cargo-target-demo cargo build --release \
      -p sequencer_service -p indexer_service -p explorer_service -p cross_zone_lock

The Bedrock node builds on first run of start-bedrock-native.sh below. It clones
logos-blockchain to ~/logos/logos-blockchain, checks out tag 0.2.1, and runs
`cargo build --release -p logos-blockchain-node`. That build is heavy (the whole
node workspace); do it well before a demo. If your shell exports CARGO_TARGET_DIR,
the node binary lands under it; the script resolves that automatically.

## Run: the transfer that works

    cd ~/logos/lez-demo-v024/demo/cross-zone-testnet

    # 1. Start the native Bedrock node (builds it on first run), wait for Online.
    ./start-bedrock-native.sh
    sleep 30
    curl -s http://localhost:18080/cryptarchia/info      # expect "state":"Online"

    # 2. Start both zones (native). This stamps fresh channels and prints the
    #    exact lock command with zone B's channel filled in.
    ./run-native.sh

    # 3. Confirm both zones produce blocks (run twice, ~10s apart; the number climbs).
    curl -s -X POST http://localhost:3040 -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}'
    curl -s -X POST http://localhost:3041 -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}'

    # 4. Fire the lock (the command run-native.sh printed):
    TARGET=$(python3 -c "import json;print(json.load(open('configs/sequencer_b.json'))['bedrock_config']['channel_id'])")
    ../../.cargo-target-demo/release/cross_zone_lock \
      --sequencer-url http://localhost:3040 --target-zone "$TARGET"

The mint is not instant: the emission lands a few blocks after the lock and the
watcher waits for Bedrock finality, so allow ~2 minutes. Watch it happen:

    # watcher records the delivery, then zone B mints (a block with 2 transactions)
    grep -iE "recorded|2 transactions" logs/seq_b.log | tail

## Confirm the result

Zone A: holder debited to 70 (100 - 30), escrow holds 30.

    curl -s -X POST http://localhost:3040 -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"getAccount","params":["65fTAPEquXmXNvJieTPdsR5FEw4fo2wLZQdS3RCpyX9a"]}'
    # -> "balance":70

Zone B: recipient holds 30 wrapped tokens (stored in the account data field, not
the native balance).

    HOLDING=$(../../.cargo-target-demo/release/cross_zone_lock --print-params \
      | python3 -c "import json,sys;print(json.load(sys.stdin)['recipient_wrapped_holding_id_base58'])")
    curl -s -X POST http://localhost:3041 -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccount\",\"params\":[\"$HOLDING\"]}"
    # -> "data":[30,0,0,...]  (30 wrapped tokens; balance:0 is the unused native balance)

Conservation: 30 locked on A equals 30 minted on B.

## Run: the transfer the network refuses

Same lock, but zone B authorizes no route, so its watcher drops the message and
nothing is minted. The Bedrock keeps running; only the zones restart.

    ./stop-native.sh
    ./run-native.sh unauthorized
    sleep 25
    TARGET=$(python3 -c "import json;print(json.load(open('configs/sequencer_b.json'))['bedrock_config']['channel_id'])")
    ../../.cargo-target-demo/release/cross_zone_lock \
      --sequencer-url http://localhost:3040 --target-zone "$TARGET"

    # zone B drops it; no mint block appears
    grep -i "dropping message" logs/seq_b.log

Zone A still shows the lock (holder 70, escrow 30); zone B mints nothing.

## Teardown

    ./stop-native.sh              # stop the zones
    ./stop-bedrock-native.sh      # stop the Bedrock node

## Ports

- localhost:3040  zone A sequencer RPC (lock target)
- localhost:3041  zone B sequencer RPC (mint lands here)
- localhost:8779  zone B indexer RPC
- localhost:18080 Bedrock node API

## Notes

- Each run stamps a fresh channel pair (a fresh process regenerates its Bedrock
  signing key, so channels cannot be reused). Always run through run-native.sh,
  which calls prepare.sh; do not reuse channels across clean runs.
- The Docker scripts (start-bedrock.sh, docker-compose.yml) are kept for reference
  but do not work on Apple Silicon (the amd64 Bedrock image hangs under emulation).
  Use the native path above.
