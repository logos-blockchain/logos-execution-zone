cargo install --path wallet --force


python3 -m venv venv
source venv/bin/activate
python3 -m pip install pyscard
python3 -m pip install mnemonic
python3 -m pip install ecdsa
python3 -m pip install pyaes

cd python

# git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git
cd keycard-py
python3 -m venv venv
source venv/bin/activate
pip install -e .



