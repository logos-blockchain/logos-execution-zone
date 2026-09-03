#!/usr/bin/env bash
# Stamp a fresh, unique channel-id pair into all zone configs before a run.
#
# A sequencer that starts on a fresh data volume regenerates its Bedrock signing
# key, so it can only own a channel it creates. Reusing a channel id across clean
# runs would leave it accredited to the previous run's key. Running this before
# each `docker compose up` (after `docker compose down -v`) keeps every run clean
# and collision-free on the shared testnet.
set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import json, os, pathlib

a = os.urandom(32)
b = os.urandom(32)
hex_a, hex_b = a.hex(), b.hex()
arr_a = list(a)
cfg = pathlib.Path("configs")

def edit(name, fn):
    p = cfg / name
    d = json.loads(p.read_text())
    fn(d)
    p.write_text(json.dumps(d, indent=2) + "\n")

edit("sequencer_a.json", lambda d: d["bedrock_config"].__setitem__("channel_id", hex_a))

def zone_b_seq(d):
    d["bedrock_config"]["channel_id"] = hex_b
    d["cross_zone"]["peers"][0]["channel_id"] = arr_a

edit("sequencer_b.json", zone_b_seq)
edit("sequencer_b_unauthorized.json", zone_b_seq)

def zone_b_idx(d):
    d["channel_id"] = hex_b
    d["cross_zone"]["peers"][0]["channel_id"] = arr_a

edit("indexer_b.json", zone_b_idx)

print("Fresh channels stamped into configs/:")
print(f"  zone A channel: {hex_a}")
print(f"  zone B channel: {hex_b}")
print()
print("Once the stack is up and both channels appear on the explorer, submit the lock:")
print()
print("  ../../.cargo-target-demo/release/cross_zone_lock \\")
print(f"    --sequencer-url http://localhost:3040 --target-zone {hex_b}")
print()
print("Then watch zone B's indexer at http://localhost:8779 for the wrapped-token mint.")
PY
