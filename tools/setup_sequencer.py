#!/usr/bin/env python3
"""Prepare a sequencer home so it only needs funding before it can join.

Creates the home, its own config, its own wallet, the Bedrock identity, and the
account the stake will be paid from (the ownership account that holds the stake
is minted later, when the node stakes). Submits nothing, so it needs no funds:
prints the account for whoever runs this to fund, and `just run-sequencer <home>`
then stakes from it and starts producing.

    tools/setup_sequencer.py ~/lez-nodes/seq-7
    tools/setup_sequencer.py ~/lez-nodes/seq-7 --sequencer http://127.0.0.1:3042
"""

import argparse
import json
import os
import re
import secrets
import subprocess
import sys

DEFAULT_CONFIG = "lez/sequencer/service/configs/debug/sequencer_config.json"
FUNDING_ACCOUNT_FILE = "stake-funding-account"
SEED_FILE = "wallet-seed"
CONFIG_FILE = "sequencer_config.json"
DEFAULT_SEQUENCER = os.environ.get("LEZ_SEQUENCER", "http://127.0.0.1:3040")


def step(message: str) -> None:
    print(f"\n==> {message}", flush=True)


def wallet(args: list[str], home: str, repo: str, stdin: str = "") -> str:
    """A wallet command against the home's own wallet."""
    print(f"    $ wallet {' '.join(args)}", flush=True)
    done = subprocess.run(
        ["cargo", "run", "--release", "-q", "-p", "wallet", "--", *args],
        input=stdin, capture_output=True, text=True, cwd=repo,
        env={**os.environ, "LEE_WALLET_HOME_DIR": os.path.join(home, "wallet")},
    )
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        raise SystemExit(f"wallet {' '.join(args)} failed")
    return done.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("home", help="directory to set up")
    ap.add_argument("--sequencer", default=DEFAULT_SEQUENCER,
                    help="RPC the node's wallet talks to")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="template to copy into the home")
    ap.add_argument("--node-url", help="Bedrock node the copied config points at")
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    home = os.path.abspath(os.path.expanduser(args.home))
    wallet_home = os.path.join(home, "wallet")
    funding_account_path = os.path.join(home, FUNDING_ACCOUNT_FILE)
    if os.path.exists(funding_account_path):
        raise SystemExit(f"{home} is already set up ({FUNDING_ACCOUNT_FILE} exists)")
    os.makedirs(wallet_home, exist_ok=True)

    step("Writing the node's own sequencer config")
    node_config = json.load(open(os.path.join(repo, args.config)))
    node_config["home"] = home
    if args.node_url:
        node_config["bedrock_config"]["node_url"] = args.node_url
    config_path = os.path.join(home, CONFIG_FILE)
    with open(config_path, "w") as handle:
        json.dump(node_config, handle, indent=4)
    print(f"    {config_path}")
    print(f"    bedrock node {node_config['bedrock_config']['node_url']}")
    print(f"    channel {node_config['bedrock_config']['channel_id']}")

    step(f"Pointing the node's wallet at {args.sequencer}")
    config = {
        "sequencers": [{"sequencer_addr": args.sequencer}],
        "seq_poll_timeout": "30s",
        "seq_tx_poll_max_blocks": 15,
        "seq_poll_max_retries": 10,
        "seq_block_poll_max_amount": 100,
        "calibration_limit": 100,
    }
    with open(os.path.join(wallet_home, "wallet_config.json"), "w") as handle:
        json.dump(config, handle, indent=4)

    step("Creating the wallet and the account the stake is paid from")
    # The first command initialises the wallet, which asks for a password on
    # stdin and prints the recovery phrase once.
    password = secrets.token_urlsafe(24)
    out = wallet(["account", "new", "public"], home, repo, stdin=password + "\n")
    account = re.search(r"account_id Public/(\S+)", out)
    mnemonic = re.search(r"Recovery phrase:\s*\n\s*(.+)", out)
    if not account:
        sys.stderr.write(out)
        raise SystemExit("could not read the new account id")
    account = account.group(1)

    seed_path = os.path.join(home, SEED_FILE)
    with open(seed_path, "w") as handle:
        handle.write(f"password: {password}\n")
        if mnemonic:
            handle.write(f"mnemonic: {mnemonic.group(1).strip()}\n")
    os.chmod(seed_path, 0o600)
    print(f"    account {account}")
    print(f"    seed and password in {seed_path} (cleartext, mode 600)")

    step("Creating the Bedrock identity")
    key = subprocess.run(
        ["cargo", "run", "--release", "-q", "-p", "sequencer_service", "--bin", "bedrock_pubkey",
         "--", config_path, "--home", home],
        capture_output=True, text=True, cwd=repo, check=True,
    ).stdout.strip().splitlines()[-1]
    print(f"    key {key}")

    with open(funding_account_path, "w") as handle:
        handle.write(account + "\n")

    print(f"""
{home} is ready.

  funding account {account}
  bedrock key     {key}
  config          {config_path}
  wallet          {wallet_home}
  seed            {seed_path}  <- wallet password and recovery phrase, in
                  the clear. Do not copy this home anywhere you would not put
                  the keys themselves.

Fund that account from a funded wallet:

    wallet auth-transfer send --from Public/<funded> --to Public/{account} --amount <n>

then start the node:

    just run-sequencer {home}

It reads the account from {FUNDING_ACCOUNT_FILE}, stakes from it, and produces
once the committee accredits it.""")


if __name__ == "__main__":
    main()
