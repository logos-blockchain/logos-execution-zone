cargo install --path wallet --force

# Install appropriate version of `keycard-py`.
git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git python/keycard-py

# Set up virtual environment.
python3 -m venv venv
source venv/bin/activate
pip install pyscard mnemonic ecdsa pyaes
pip install -e python/keycard-py