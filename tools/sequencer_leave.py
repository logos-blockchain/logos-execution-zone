#!/usr/bin/env python3
"""Unstake a sequencer, releasing its stake to a destination account.

Takes the node's home so it can read the key, looks the key up in the live
stake config to find the ownership account holding its stake, and submits the
unstake request. The seat is released a finality later, and the balance moves
when a sequencer includes the FinalizeUnstake.

    tools/sequencer_leave.py ~/lez-nodes/seq-3
    tools/sequencer_leave.py ~/lez-nodes/seq-3 --destination <account>
    tools/sequencer_leave.py ~/lez-nodes/seq-3 --amount 149   # partial, >= minimum
"""

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from committee_watch import CONFIG_SEED, decode_stake_config, pda, program_id, rpc

DEFAULT_CONFIG = "lez/sequencer/service/configs/debug/sequencer_config.json"
DEFAULT_WALLET = "lez/wallet/configs/debug"
DEFAULT_DESTINATION = "CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r"
DEFAULT_SEQUENCER = os.environ.get("LEZ_SEQUENCER", "http://127.0.0.1:3040")


def run(cmd: list[str], cwd: str) -> str:
    print(f"    $ {' '.join(cmd)}", flush=True)
    done = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return done.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("home", help="path to the node's home")
    ap.add_argument("--destination", default=DEFAULT_DESTINATION,
                    help="account credited once FinalizeUnstake runs")
    ap.add_argument("--amount", type=int, help="defaults to the whole stake")
    ap.add_argument("--wallet", help="defaults to the home's own wallet, else the debug one")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--sequencer", default=DEFAULT_SEQUENCER, help="any sequencer's RPC")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--dry-run", action="store_true", help="print the request, submit nothing")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    home = os.path.abspath(os.path.expanduser(args.home))
    # The stake was made by the home's wallet, and only it can sign the release.
    wallet = args.wallet or (os.path.join(home, "wallet")
                             if os.path.isdir(os.path.join(home, "wallet"))
                             else os.path.join(repo, DEFAULT_WALLET))
    if not os.path.isdir(home):
        raise SystemExit(f"no such home: {home}")

    print(f"\n==> Reading {os.path.basename(home)}'s Bedrock key")
    key = run(
        ["cargo", "run", "--release", "-q", "-p", "sequencer_service", "--bin", "bedrock_pubkey",
         "--", os.path.join(repo, args.config), "--home", home],
        cwd=repo,
    ).strip().splitlines()[-1]
    print(f"    key {key}")

    config = decode_stake_config(
        bytes(rpc(args.sequencer, "getAccount", [pda(program_id(repo), CONFIG_SEED)])["data"])
    )
    entry = config["entries"].get(key)
    if entry is None:
        raise SystemExit(f"{key} has no stake entry; nothing to unstake")

    amount = args.amount if args.amount is not None else entry["staked"]
    remaining = entry["staked"] - amount
    if remaining and remaining < config["minimum"]:
        raise SystemExit(
            f"releasing {amount} would leave {remaining}, under the {config['minimum']} minimum; "
            "release the whole stake or leave at least the minimum"
        )

    print(f"\n==> Releasing {amount} of {entry['staked']} from {entry['owner']} "
          f"to {args.destination}")
    if args.dry_run:
        print("    --dry-run: submitting nothing")
        return

    print(run(
        ["cargo", "run", "--release", "-q", "-p", "sequencer_service", "--features",
         "submit_stake", "--bin", "submit_stake", "--", "--wallet", wallet,
         "unstake-request",
         "--ownership-account", entry["owner"], "--amount", str(amount),
         "--destination", args.destination],
        cwd=repo,
    ).strip())
    print("\nThe seat goes a finality later; the balance moves when a sequencer "
          "includes the FinalizeUnstake.")


if __name__ == "__main__":
    main()
