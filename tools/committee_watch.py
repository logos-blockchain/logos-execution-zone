#!/usr/bin/env python3
"""Show the LEZ stake config and the live Bedrock committee side by side.

The two disagree on purpose while a change is settling: committee membership
follows finalized state, so a fresh stake is staked-but-not-accredited for a
finality, and a removal stays accredited for a while after the stake goes.

    tools/committee_watch.py
    tools/committee_watch.py --watch 5
    tools/committee_watch.py --sequencer http://127.0.0.1:3041
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request

# lez/programs/sequencer_stake/core/src/lib.rs
CHANNEL_INSCRIBE_OPCODE = 17
CONFIG_SEED = b"/LEZ/v0.3/MinSequencerStake/0000"
SINK_SEED = b"/LEZ/v0.3/SlashedStakeSink/00000"
# lee/state_machine/core/src/program/mod.rs
PDA_PREFIX = b"/LEE/v0.2/AccountId/PDA/" + b"\0" * 8

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for char in text:
        n = n * 58 + B58.index(char)
    raw = n.to_bytes(32, "big")
    return raw


def http_get(url: str):
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.load(resp)


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(url, body.encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.load(resp)
    if "error" in payload:
        raise RuntimeError(f"{method}: {payload['error']}")
    return payload["result"]


def program_id(repo: str, name: str = "SEQUENCER_STAKE_ID") -> list[int]:
    """A program's id is a build artifact; getProgramIds does not list it."""
    hits = sorted(
        glob.glob(
            os.path.join(repo, "target", "*", "build", "programs-*", "out", "lez", "programs", "mod.rs")
        ),
        key=os.path.getmtime,
        reverse=True,
    )
    if not hits:
        raise SystemExit("no generated programs mod.rs under target/; build once first")
    m = re.search(rf"{name}:\s*\[u32;\s*8\]\s*=\s*\[([^\]]+)\]", open(hits[0]).read())
    if not m:
        raise SystemExit(f"{name} not found in {hits[0]}")
    return [int(x) for x in m.group(1).replace(" ", "").split(",") if x]


def pda(pid: list[int], seed: bytes) -> str:
    return b58encode(hashlib.sha256(PDA_PREFIX + struct.pack("<8I", *pid) + seed).digest())


def program_account_id(pid: list[int]) -> str:
    """Encode the image ID's little-endian words as a base58 account ID."""
    return b58encode(struct.pack("<8I", *pid))


def stake_config(repo: str, sequencer: str) -> dict:
    """Read the stake program's config shard."""
    pid = program_id(repo)
    program = program_account_id(pid)
    account = rpc(
        sequencer,
        "getAccountView",
        [{"account_id": pda(pid, CONFIG_SEED), "program_account_id": program}],
    )
    return decode_stake_config(bytes(account["data"]["shards"][program]))


class Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise RuntimeError(f"truncated at {self.pos}")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u128(self) -> int:
        return int.from_bytes(self.take(16), "little")


def decode_stake_config(data: bytes) -> dict:
    r = Reader(data)
    # `channel_params: Option<ChannelParams>` — one borsh tag byte, then the
    # three values when present.
    if r.take(1)[0]:
        minimum, timeframe, timeout = r.u128(), r.u32(), r.u32()
    else:
        minimum = timeframe = timeout = None
    entries = {}
    for _ in range(r.u32()):
        key = r.take(32).hex()
        entries[key] = {
            "owner": b58encode(r.take(32)),
            "staked": r.u128(),
            "pending": r.u128(),
        }
    for e in entries.values():
        e["net"] = max(e["staked"] - e["pending"], 0)
    return {
        "minimum": minimum,
        "posting_timeframe": timeframe,
        "posting_timeout": timeout,
        "entries": entries,
    }


def seat_label(
    key: str, entry: dict | None, accredited: list[str], turn: int, minimum: int
) -> str:
    """Where a key sits between the stake config and the live committee.

    The two lag each other by design, so a key can hold a seat its stake no
    longer backs, or be paid up with no seat yet.
    """
    if key in accredited:
        idx = accredited.index(key)
        seat = f"idx {idx}" + ("  <- turn" if idx == turn else "")
        if entry is None or entry["net"] < minimum:
            return f"{seat}   [leaving]"
        return seat
    if entry and entry["net"] >= minimum:
        return "not accredited   [joining]"
    return "not accredited"


def authorized_index(live: dict, slot: int) -> tuple[int, int]:
    """Whose turn it is at `slot` and when it started, mirroring round_robin.

    The channel stores only who wrote the tip; the turn is derived, and keeps
    advancing over a silent sequencer once its timeout elapses. A prediction
    for `slot`: L1 decides at the slot that applies the block, so the two
    disagree either side of a boundary.
    """
    keys = len(live["accredited_keys"])
    tip_sequencer = live["tip_sequencer"]
    tip_slot = live["tip_slot"]
    turn_start = live["tip_sequencer_starting_slot"]
    timeframe = live["posting_timeframe"]
    timeout = live["posting_timeout"]

    since_tip = max(slot - tip_slot, 0)
    held_for = max(slot - turn_start, 0)

    if timeout and since_tip >= timeout:
        elapsed = since_tip // timeout
        return (tip_sequencer + elapsed) % keys, tip_slot + elapsed * timeout
    if timeframe:
        elapsed = held_for // timeframe
        return (tip_sequencer + elapsed) % keys, turn_start + elapsed * timeframe
    return tip_sequencer, turn_start


def last_inscribed(node: str, channel: str, slot_from: int, slot_to: int) -> dict:
    """Highest LEZ block each key inscribed, and the L1 slot it landed in.

    Read off L1 rather than asked of a node: the inscription's signer is the
    only authority on who wrote a block. Finalized history only, so this trails
    the tip by the finality depth.
    """
    latest: dict[str, tuple[int, int]] = {}
    for start in range(slot_from, slot_to + 1, 500):
        end = min(start + 499, slot_to)
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
                    if len(raw) < 8:
                        continue  # not a block: garbage, or a non-block payload
                    block_id = struct.unpack("<Q", raw[:8])[0]
                    signer = payload["signer"]
                    if signer not in latest or block_id > latest[signer][0]:
                        latest[signer] = (block_id, slot)
    return latest


def snapshot(args) -> str:
    pid = program_id(args.repo)
    sink_id = pda(pid, SINK_SEED)

    stake = stake_config(args.repo, args.sequencer)
    sink = rpc(args.sequencer, "getAccountBalance", [sink_id])
    # Slot first: a slot read after the channel state would be newer than it,
    # inflating `since_tip` and rotating the turn early.
    info = http_get(f"{args.node}/cryptarchia/info")["cryptarchia_info"]
    slot, lib = info["slot"], info["lib_slot"]
    live = http_get(f"{args.node}/channel/{args.channel}")
    accredited = live["accredited_keys"]

    turn, turn_start = authorized_index(live, slot)
    stale = slot - live["tip_slot"]

    out = []
    params = (
        "channel params unset"
        if stake["minimum"] is None
        else f"minimum stake {stake['minimum']}    "
        f"turn {stake['posting_timeframe']}s / timeout {stake['posting_timeout']}s"
    )
    out.append(f"{params}    burned in sink {sink}")
    # How much of the turn is left, so a reading near a boundary looks like one.
    window = live["posting_timeout"] if stale >= live["posting_timeout"] > 0 else 0
    window = window or live["posting_timeframe"]
    left = f", {window - (slot - turn_start)} left" if window else ""
    out.append(
        f"slot {slot}   turn: idx {turn} (since {turn_start}{left})   "
        f"tip: idx {live['tip_sequencer']} at slot {live['tip_slot']} ({stale} slots ago)"
    )
    out.append(
        f"timeframe {live['posting_timeframe']}  timeout {live['posting_timeout']}  "
        f"threshold {live['configuration_threshold']}"
    )
    built = last_inscribed(args.node, args.channel, max(lib - args.history, 0), lib)

    out.append("")
    out.append(
        f"{'sequencer key':<20} {'staked':>8} {'net':>8} {'last block':>11} {'ago':>7}  committee"
    )

    for key in sorted(set(stake["entries"]) | set(accredited)):
        e = stake["entries"].get(key)
        staked = f"{e['staked']}" if e else "-"
        net = f"{e['net']}" if e else "-"

        if key in built:
            block_id, at_slot = built[key]
            last, ago = str(block_id), f"{slot - at_slot}s"
        else:
            last, ago = "-", "-"

        # Before genesis sets the params nothing can meet a minimum, so no
        # entry is a candidate.
        minimum = stake["minimum"]
        seat = seat_label(key, e, accredited, turn, float("inf") if minimum is None else minimum)
        out.append(
            f"{key[:20]} {staked:>8} {net:>8} {last:>11} {ago:>7}  {seat}"
        )

    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sequencer", default=os.environ.get("LEZ_SEQUENCER", "http://127.0.0.1:3040"),
                    help="any sequencer's RPC")
    ap.add_argument("--node", default=os.environ.get("LEZ_NODE", "http://127.0.0.1:18080"),
                    help="a Bedrock node")
    ap.add_argument("--channel", default="01" * 32)
    ap.add_argument("--repo", default=".", help="repo root, for the generated program id")
    ap.add_argument("--history", type=int, default=400,
                    help="slots of finalized L1 history to scan for last-built blocks")
    ap.add_argument("--watch", type=float, metavar="SECONDS", help="redraw every SECONDS")
    args = ap.parse_args()

    if args.watch is None:
        print(snapshot(args))
        return

    while True:
        try:
            body = snapshot(args)
        except (urllib.error.URLError, RuntimeError, OSError) as err:
            body = f"unavailable: {err}"
        sys.stdout.write("\033[2J\033[H")
        print(f"{time.strftime('%H:%M:%S')}   sequencer {args.sequencer}   bedrock {args.node}\n")
        print(body, flush=True)
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
