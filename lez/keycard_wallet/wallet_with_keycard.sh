#!/bin/bash

cargo install --path lez/wallet --force

# Install appropriate version of `keycard-py`.
git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git lez/keycard_wallet/python/keycard-py

# Set up virtual environment.
python3 -m venv venv
source venv/bin/activate
pip install pyscard mnemonic ecdsa pyaes
pip install -e lez/keycard_wallet/python/keycard-py