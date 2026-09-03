# Cross-zone bridge demo on the live testnet Bedrock (real nodes)

Two LEZ zones, each running the real v0.2.4 `sequencer_service` + `indexer_service`
containers, settling on the live shared testnet Bedrock L1
(`http://65.109.51.37:18080`, unauthenticated). No local Bedrock. A holder locks a
balance on zone A; zone B's watcher carries the message, its indexer verifies it,
and the wrapped token is minted on zone B. A second run shows zone B refusing the
crossing when its route is not authorized.

## What is real, what is not

Real: two independent zone deployments (separate sequencer + indexer processes),
real channels created on the live testnet Bedrock, real cross-zone watcher and
indexer-side verification, real settlement over the L1.

Not real: proving is dev-mode (blocks in seconds), and zone A's lockable balance
is seeded at genesis rather than by a live L1 deposit (in this release a deposit
lands in a vault account the lock cannot spend).

## Prerequisites

- Docker with access to `harbor.status.im`: `docker login harbor.status.im`.
- The testnet Bedrock reachable: `curl http://65.109.51.37:18080/cryptarchia/info`
  returns JSON with `"state":"Online"`.
- The lock tool built once (real guests):
  `cd ~/logos/lez-demo-v024 && CARGO_TARGET_DIR=.cargo-target-demo cargo build -p cross_zone_lock --release`
  The binary lands at `.cargo-target-demo/release/cross_zone_lock`.

## Run: the transfer that works

    cd ~/logos/lez-demo-v024/demo/cross-zone-testnet
    ./prepare.sh                 # stamps fresh channel ids, prints the lock command
    docker compose up            # pulls v0.2.4 images, starts both zones + zone B explorer

Wait until both zones are producing blocks (watch the logs, or the two fresh
channels appearing on the testnet explorer). Then submit the lock with the command
`prepare.sh` printed, for example:

    ../../.cargo-target-demo/release/cross_zone_lock \
      --sequencer-url http://localhost:3040 --target-zone <zone-B-channel-hex>

Watch the mint on zone B:
- Browser: http://localhost:8080 (zone B explorer), the recipient's wrapped
  holding goes to 30.
- Zone A conservation: the escrow holds 30 and the holder drops from 100 to 70
  (visible in zone A's sequencer at localhost:3040).

## Run: the transfer the network refuses

Start clean so zone B comes up with the unauthorized config:

    docker compose down -v
    ./prepare.sh
    docker compose -f docker-compose.yml -f docker-compose.unauthorized.yml up

Submit the same lock command. The lock lands on zone A, but zone B's watcher logs

    WARN  Watcher dropping message from peer ...: no route from that source
          program to that target

and nothing is minted on zone B. Zone A still shows the 30 in escrow.

## Teardown and re-runs

    docker compose down -v       # stop and wipe the zone volumes

Always run `./prepare.sh` again before a fresh `up`: each run needs new channel
ids, because a sequencer on a fresh volume regenerates its Bedrock signing key and
can only own a channel it creates.

## Ports

- `localhost:3040` zone A sequencer RPC (lock target)
- `localhost:3041` zone B sequencer RPC
- `localhost:8779` zone B indexer RPC
- `localhost:8080` zone B explorer UI

## How it is wired

- Both zones' `bedrock_config.node_url` points at the testnet Bedrock; `funding_key`
  is the node-custodied faucet key, which the node funds block-publishes from with
  no auth.
- Zone A seeds the holder via `supply_bridge_lock_holding` in its genesis.
- Zone B's `cross_zone` block authorizes the `bridge_lock -> wrapped_token` route
  from zone A's channel; supplying it also seeds zone B's inbox and wrapped-token
  config at genesis. The unauthorized variant is the same with an empty
  `allowed_routes`.
- `prepare.sh` keeps the four configs consistent: zone A's channel hex, zone B's
  channel hex, and zone A's channel repeated as the peer id inside zone B's config.
