#!/usr/bin/env python3
"""Check the LEZ block heights inscribed on a channel are a gapless run.

Reads finalized L1 blocks and decodes every channel inscription, so it sees
what the channel actually carries rather than what a sequencer reports. Walks
back until it reaches genesis unless `--from` says where to start. Exits
non-zero if the run has a gap, a duplicate, a step backwards, or never reaches
genesis.

    tools/channel_health.py
    tools/channel_health.py --from 2614000
    tools/channel_health.py --node http://127.0.0.1:18080 --channel 0101...
"""

import argparse
import json
import os
import struct
import sys
import urllib.request

# lez/programs/sequencer_stake/core/src/lib.rs
CHANNEL_INSCRIBE_OPCODE = 17
# A header is u64 + two 32-byte hashes + timestamp + signature, so anything
# shorter is not a block. Without this a short payload's first 8 bytes read as
# a nonsense height.
MIN_BLOCK_LEN = 144
SLOTS_PER_REQUEST = 500
# lee/state_machine/core/src/lib.rs
GENESIS_BLOCK_ID = 1
# Slots to walk back per step when looking for genesis.
LOOKBACK_STEP = 6000


def paint(text: str, code: str) -> str:
    """Colour, unless the output is being piped somewhere."""
    return text if not sys.stdout.isatty() else f"\033[{code}m{text}\033[0m"


def mark(ok: bool) -> str:
    return paint("\u2714", "32") if ok else paint("\u2718", "31")


def http_get(url: str):
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)


def inscriptions(node: str, channel: str, slot_from: int, slot_to: int):
    """Every inscription on the channel in `slot_from..slot_to`, in L1 order."""
    blocks, others = [], []
    for start in range(slot_from, slot_to + 1, SLOTS_PER_REQUEST):
        end = min(start + SLOTS_PER_REQUEST - 1, slot_to)
        for block in http_get(f"{node}/cryptarchia/blocks?slot_from={start}&slot_to={end}"):
            slot = block["header"]["slot"]
            for tx in block.get("transactions", []):
                for op in tx.get("mantle_tx", {}).get("ops", []):
                    if op.get("opcode") != CHANNEL_INSCRIBE_OPCODE:
                        continue
                    payload = op["payload"]
                    if payload.get("channel_id") != channel:
                        continue
                    raw = bytes.fromhex(payload["inscription"])
                    signer = (payload.get("signer") or "?")[:8]
                    if len(raw) < MIN_BLOCK_LEN:
                        others.append((slot, signer, len(raw), raw[:16].hex()))
                    else:
                        blocks.append((slot, struct.unpack("<Q", raw[:8])[0], signer))
    return sorted(blocks), others


def report(blocks, others, scanned) -> bool:
    """Prints the run and returns whether it holds."""
    slot_from, slot_to, tip = scanned
    print(f"scanned slots {slot_from}..{slot_to} (tip {tip})")
    print(f"inscriptions carrying a block: {len(blocks)}   other payloads: {len(others)}")
    for slot, signer, size, prefix in others:
        print(f"  non-block at slot {slot} by {signer} ({size} bytes, {prefix})")

    if not blocks:
        print(f"\n{paint('\u2718  no inscriptions in that range', '1;31')}")
        return False

    ids = [block_id for _, block_id, _ in blocks]
    print(f"first block_id {ids[0]} at slot {blocks[0][0]}, "
          f"last {ids[-1]} at slot {blocks[-1][0]}")

    seen, dupes, steps = {}, [], []
    previous = None
    for slot, block_id, signer in blocks:
        if block_id in seen:
            dupes.append((block_id, seen[block_id], (slot, signer)))
        else:
            seen[block_id] = (slot, signer)
        if previous is not None and block_id != previous + 1:
            steps.append((previous, block_id, slot, signer))
        previous = block_id
    missing = sorted(set(range(ids[0], ids[-1] + 1)) - set(ids))

    from_genesis = ids[0] == GENESIS_BLOCK_ID

    print()
    print(f"{mark(from_genesis)} reaches genesis (block {GENESIS_BLOCK_ID})")
    print(f"{mark(not missing)} no gaps in {ids[0]}..{ids[-1]}"
          + (f" ({len(missing)} missing)" if missing else ""))
    if missing:
        print("    " + ", ".join(map(str, missing[:40])) + (" ..." if len(missing) > 40 else ""))
    print(f"{mark(not dupes)} no duplicates" + (f" ({len(dupes)})" if dupes else ""))
    for block_id, first, second in dupes[:10]:
        print(f"    block {block_id}: slot {first[0]} by {first[1]}, "
              f"again slot {second[0]} by {second[1]}")
    print(f"{mark(not steps)} no non-consecutive LEZ blocks in L1"
          + (f" ({len(steps)})" if steps else ""))
    for previous_id, block_id, slot, signer in steps[:10]:
        print(f"    {previous_id} -> {block_id} at slot {slot} by {signer}")

    ok = from_genesis and not (missing or dupes or steps)
    print()
    if ok:
        print(paint(f"\u2714  {len(blocks)} blocks, {ids[0]}..{ids[-1]}, "
                    "gapless from genesis", "1;32"))
    else:
        broken = []
        if not from_genesis:
            broken.append(f"starts at {ids[0]}, not genesis")
        if missing:
            broken.append(f"{len(missing)} missing")
        if dupes:
            broken.append(f"{len(dupes)} duplicated")
        if steps:
            broken.append(f"{len(steps)} out of order")
        print(paint("\u2718  " + ", ".join(broken), "1;31"))
    return ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default=os.environ.get("LEZ_NODE", "http://127.0.0.1:18080"),
                    help="a Bedrock node")
    ap.add_argument("--channel", default="01" * 32)
    ap.add_argument("--from", dest="slot_from", type=int,
                    help="first slot to scan; without it, walks back to genesis")
    args = ap.parse_args()

    info = http_get(f"{args.node}/cryptarchia/info")["cryptarchia_info"]
    tip, lib = info["slot"], info["lib_slot"]

    slot_from = args.slot_from if args.slot_from is not None else max(lib - LOOKBACK_STEP, 0)
    blocks, others = inscriptions(args.node, args.channel, slot_from, lib)

    # A scan that starts mid-chain checks a suffix, not the run from genesis.
    while args.slot_from is None and slot_from > 0:
        if blocks and blocks[0][1] == GENESIS_BLOCK_ID:
            break
        earlier_to = slot_from - 1
        slot_from = max(slot_from - LOOKBACK_STEP, 0)
        print(f"first id is not genesis, extending back to slot {slot_from}")
        earlier, earlier_others = inscriptions(args.node, args.channel, slot_from, earlier_to)
        blocks, others = earlier + blocks, earlier_others + others

    if not report(blocks, others, (slot_from, lib, tip)):
        sys.exit(1)


if __name__ == "__main__":
    main()
