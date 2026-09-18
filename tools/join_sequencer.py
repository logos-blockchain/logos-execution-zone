#!/usr/bin/env python3
"""Stake a new sequencer into the committee and start it producing.

Given a wallet and a funded account whose key it holds, this mints a fresh
ownership account, stakes the new node's key, waits for Bedrock to accredit it,
and then runs the sequencer.

    tools/join_sequencer.py --home ~/lez-nodes/seq-1 \\
        --wallet lez/wallet/configs/debug \\
        --funding-account CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r

The home holds the node's db, both signing keys and its log, matching what
`just run-sequencer` lays down.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from committee_watch import decode_stake_config, pda, program_id  # noqa: E402

DEFAULT_CONFIG = "lez/sequencer/service/configs/debug/sequencer_config.json"
# The debug genesis funds this account, and the debug wallet holds its key.
DEFAULT_WALLET = "lez/wallet/configs/debug"
DEFAULT_FUNDING = "CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r"
# One pair of env vars points every tool at a network.
DEFAULT_NODE = os.environ.get("LEZ_NODE")
DEFAULT_SEQUENCER = os.environ.get("LEZ_SEQUENCER", "http://127.0.0.1:3040")
CONFIG_SEED = b"/LEZ/v0.3/MinSequencerStake/0000"
# Written once staked: names the account holding the stake, and its presence
# is what stops a later run from staking again.
OWNERSHIP_ACCOUNT_FILE = "stake-ownership-account"


def step(msg: str) -> None:
    print(f"\n==> {msg}", flush=True)


def run(cmd: list[str], env: dict | None = None, cwd: str | None = None) -> str:
    print(f"    $ {' '.join(cmd)}", flush=True)
    done = subprocess.run(
        cmd, capture_output=True, text=True, env={**os.environ, **(env or {})}, cwd=cwd
    )
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return done.stdout


def http_get(url: str):
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.load(resp)


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(url, body.encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.load(resp)
    if "error" in payload:
        raise SystemExit(f"{method} failed: {payload['error']}")
    return payload["result"]


def free_port(preferred: int) -> int:
    """`preferred`, or the next port nothing is listening on."""
    for port in range(preferred, preferred + 50):
        with socket.socket() as probe:
            try:
                probe.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise SystemExit(f"no free port in {preferred}..{preferred + 49}")


def stake_config(repo: str, sequencer: str) -> dict:
    """The live minimum and per-key entries, straight from LEZ state."""
    account = pda(program_id(repo), CONFIG_SEED)
    return decode_stake_config(bytes(rpc(sequencer, "getAccount", [account])["data"]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True, help="home dir for the joining sequencer")
    ap.add_argument("--wallet", default=DEFAULT_WALLET, help="wallet home (holds wallet_config.json)")
    ap.add_argument("--funding-account", default=DEFAULT_FUNDING, help="funded; the wallet holds its key")
    ap.add_argument("--amount", type=int, help="defaults to the live minimum")
    ap.add_argument("--port", type=int, default=3041)
    ap.add_argument("--metrics-address", default="0.0.0.0:9091")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--node", default=DEFAULT_NODE, help="defaults to the config's node_url")
    ap.add_argument("--sequencer", default=DEFAULT_SEQUENCER, help="an existing sequencer")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--timeout", type=int, default=180, help="seconds to wait for accreditation")
    ap.add_argument("--no-run", action="store_true", help="stop after accreditation")
    ap.add_argument(
        "--no-log",
        action="store_true",
        help="don't tee into <home>/sequencer.log; for a caller that already "
        "logs the whole run, like `just run-sequencer`",
    )
    ap.add_argument(
        "--stake-only",
        action="store_true",
        help="submit the stake and exit without waiting for accreditation, "
        "for staking several nodes before waiting on any of them",
    )
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    wallet = os.path.abspath(args.wallet)
    home = os.path.abspath(args.home)
    os.makedirs(home, exist_ok=True)
    funding = args.funding_account.removeprefix("Public/")
    bedrock = json.load(open(os.path.join(repo, args.config)))["bedrock_config"]
    channel = bedrock["channel_id"]
    args.node = args.node or bedrock["node_url"]

    step("Reading the joining node's Bedrock key")
    key = run(
        ["cargo", "run", "--release", "-q", "-p", "sequencer_service", "--bin", "bedrock_pubkey",
         "--", args.config, "--home", home],
        cwd=repo,
    ).strip().splitlines()[-1]
    print(f"    key {key}")

    try:
        live = http_get(f"{args.node}/channel/{channel}")
    except urllib.error.HTTPError as err:
        if err.code != 404:
            raise
        raise SystemExit(
            f"channel {channel} does not exist on {args.node} yet. The first node creates "
            "it: run `just run-sequencer <home>` and let it produce a block, then retry."
        ) from err
    config = stake_config(repo, args.sequencer)
    entry = config["entries"].get(key)
    minimum = config["minimum"]
    ownership = entry["owner"] if entry else None

    def record_ownership() -> None:
        """The account holding the stake, and the marker that we staked."""
        if ownership:
            with open(os.path.join(home, OWNERSHIP_ACCOUNT_FILE), "w") as handle:
                handle.write(ownership + "\n")

    if key in live["accredited_keys"]:
        print("    already accredited; skipping the stake")
        record_ownership()
    else:
        if entry and entry["net"] >= minimum:
            # A previous run already staked; only accreditation is outstanding.
            step(f"Key already staked ({entry['net']}); waiting on accreditation")
        else:
            # The program refuses a fresh account once the key has an entry, so
            # a top-up must reuse the one the entry names.
            if entry:
                ownership = entry["owner"]
                amount = args.amount or (minimum - entry["net"])
                step(f"Topping up {ownership} by {amount}")
            else:
                amount = args.amount or minimum
                step(f"Creating a fresh ownership account (staking {amount})")
                out = run(
                    ["cargo", "run", "--release", "-q", "-p", "wallet", "--",
                     "account", "new", "public"],
                    env={"LEE_WALLET_HOME_DIR": wallet},
                    cwd=repo,
                )
                match = re.search(r"account_id Public/(\S+)", out)
                if not match:
                    raise SystemExit(f"could not parse the new account id from:\n{out}")
                ownership = match.group(1)
                print(f"    ownership account {ownership}")

            # The stake fails inside the guest if the funds are short, so say
            # so here, where the fix is obvious.
            balance = rpc(args.sequencer, "getAccount", [funding])["balance"]
            if balance < amount:
                raise SystemExit(
                    f"{funding} holds {balance}, short of the {amount} to stake. Fund it "
                    f"from a funded wallet:\n\n    wallet auth-transfer send "
                    f"--from Public/<funded> --to Public/{funding} --amount <n>"
                )

            step("Submitting the stake")
            print(run(
                ["cargo", "run", "--release", "-q", "-p", "sequencer_service", "--features",
                 "submit_stake", "--bin", "submit_stake", "--", "--wallet", wallet, "stake",
                 "--funding-account", funding, "--ownership-account", ownership,
                 "--sequencer-key", key, "--amount", str(amount)],
                cwd=repo,
            ).strip())

        record_ownership()

        if args.stake_only:
            print("\n--stake-only: not waiting for accreditation")
            return

        step(f"Waiting up to {args.timeout}s for Bedrock to accredit the key")
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                if key in http_get(f"{args.node}/channel/{channel}")["accredited_keys"]:
                    break
            except (urllib.error.URLError, OSError) as err:
                print(f"    bedrock unavailable: {err}")
            print(f"    not yet accredited, {int(deadline - time.time())}s left")
            time.sleep(5)
        else:
            raise SystemExit(
                "timed out waiting for accreditation; the stake tx may still be settling "
                "(committee entry follows finalized state) — re-run to resume"
            )
        print("    accredited")

    if args.no_run:
        print("\n--no-run: stopping before starting the sequencer")
        return

    # Every node after the first would otherwise collide on the defaults, and
    # the metrics listener fails late, after the stake has already gone out.
    port = free_port(args.port)
    metrics_host, _, metrics_port = args.metrics_address.rpartition(":")
    metrics = f"{metrics_host}:{free_port(int(metrics_port))}"
    if port != args.port or metrics != args.metrics_address:
        print(f"    ports in use; using --port {port} --metrics-address {metrics}")

    step(f"Starting the sequencer on port {port}")
    cargo_argv = [
        "cargo", "run", "--release", "-p", "sequencer_service", "--",
        os.path.join(repo, args.config), "--home", home,
        "--port", str(port), "--metrics-address", metrics,
    ]
    env = {**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info")}
    os.chdir(os.path.join(repo, "lez", "sequencer", "service"))
    if args.no_log:
        os.execvpe("cargo", cargo_argv, env)

    # Appended, not truncated, and in the home the node already owns: a wedge is
    # only legible next to the run before it.
    log = os.path.join(home, "sequencer.log")
    with open(log, "a") as handle:
        handle.write(
            f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%S%z')}  {os.path.basename(home)}"
            f"  rpc :{port}  metrics :{metrics} ===\n"
        )
    print(f"    log {log}")
    os.execvpe(
        "sh",
        ["sh", "-c", f"{shlex.join(cargo_argv)} 2>&1 | tee -a {shlex.quote(log)}"],
        env,
    )


if __name__ == "__main__":
    main()
