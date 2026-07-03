#!/bin/bash

cargo install --path lez/wallet --force

# `pyscard` is only needed by tests/force_unpower.py, a test-only helper that simulates a card
# power loss via PC/SC — the wallet CLI itself is pure Rust and talks to the card directly via
# `keycard-rs`.
python3 -m venv venv
source venv/bin/activate
pip install pyscard