This tutorial walks you through using Keycard with Wallet CLI. Keycard is optional hardware that can offer enhance security to a LEZ wallet. A LEZ wallet that utilizes Keycard does not store any secret keys for public accounts (eventually, this will extend to private accounts). Instead, Wallet CLI retrieves the appropriate public keys and signatures from Keycard.


## Keycard Setup

### Required hardware
- Keycard (Blank) - a Keycard, directly, from Keycard.tech cannot (currently) be updated to support LEE.
- Smartcard reader

### Firmware installation
Installation:

1. Install `math.cap` on your keycard; this process only needs to be done once. (TODO: can this cap file be shared externally?)
    - `java -jar gp.jar --key c212e073ff8b4bbfaff4de8ab655221f --load math.cap`
2. Install `keycard-desktop` from [github](https://github.com/choppu/keycard-desktop)
    - Keycard Desktop is used to install the LEE key protocol to a blank keycard.
    - Select (Re)Install Applet and upload the cap. (TODO: double check that we can upload to repo)
    ![keycard-desktop.png](keycard-desktop.png)

## Wallet with Keycard
Keycard functionality is available to Wallet CLI by setting up the following Python virtual environment:

```bash
# Setup virtual environment.
python3 -m venv venv
source venv/bin/activate
python3 -m pip install pyscard
python3 -m pip install mnemonic
python3 -m pip install ecdsa
python3 -m pip install pyaes

# Install appropriate version of `keycard-py`.
cd python
# Need to use local version till fix applet
git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git
cd keycard-py
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**Important**: Keycard wallet commands only work within the virtual environment.
```bash
# In the root of LEE repo:
source venv/bin/activate
```

## Keycard Commands

### Keycard

| Command                | Description                                                             |
|------------------------|-------------------------------------------------------------------------|
| `wallet keycard available`        | Checks whether Keycard is accessible                         |
| `wallet keycard load`             | Loads a new mnemonic phrase onto Keycard                     |
| `wallet keycard get-private-keys` | Retrieves private account keys (nsk, vsk) given a ChainIndex |
| `wallet help`                     | Help                                                         |

### 1. Check keycard availability
```bash
wallet keycard available

# Output:
✅ Keycard is available.
```

### 2. Load a new mnemonic phrase
```bash
wallet keycard load --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"

# Output:
Keycard PIN: # Enter Keycard pin
✅ Keycard is now connected to wallet.
```

### 3. Ger private key
```bash
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/0"

# Output:
Keycard PIN: # Enter Keycard pin
nsk: 55e505bf925e536c843a12ebc08c41ca5f4761eeeb7fa33725f0b44e6f1ac2e4
vsk: 30f798893977a7b7263d1f77abf58e11e014428c92030d6a02fe363cceb41ffa
```
### Pinata (testnet)
| Command                | Description                                                         |
|------------------------|---------------------------------------------------------------------|
| `wallet pinata claim`  | Accepts ChainIndex (key path) for public account to send pinata reward to|

- See example in Authenicated-transfers examples.

### Authenticated-transfer program

| Command                | Description                                                         |
|------------------------|---------------------------------------------------------------------|
| `wallet auth-transfer init`  | Accepts ChainIndex (key path) for public account to initialize|
| `wallet auth-transfer send`  | Accepts ChainIndices (key paths) for `from` and `to`          |

1. Initialize public account.
```bash
wallet auth-transfer init --key-path "m/44'/60'/0'/0/0"

#Output
Keycard PIN: # Enter Keycard pin
Transaction hash is 49c16940493e1618c393645c1211b5c793d405838221c29ac6562a8a4b11c5a7
Transaction data is Public(PublicTransaction { message: Message { program_id: "adbf67b01ded1e29c7a0b7b1b580e6ad4166a8fd52b57bf629fe78d4c779a48a", account_ids: [Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP], nonces: [Nonce(0)], instruction_data: [0, 0, 0, 0] }, witness_set: WitnessSet { signatures_and_public_keys: [(9b43433cce6f0c5c268e408c0e300b8767c11f462a2fbea50b22b3f52ddeea86b5c3e959c1d3625603e4d22b8ccff62caa7819e28761cec9bbfb32b87a9e0c81, 0a5873812f910609da22d8aef918632677f3208faa3cec2b692f3e4c37ffd11d)] } })
Stored persistent accounts at /home/mara/.nssa/wallet/storage.json
```

2. Fund initialized public account with Pinata reward.
```bash
wallet pinata claim --key-path "m/44'/60'/0'/0/0"

#Output:
Keycard PIN: # Enter Keycard pin
Computing solution for pinata...
Found solution 989106 in 33.739525ms
Transaction hash is fd320c01f5469e62d2486afa1d9d5be39afcca0cd01d1575905b7acd95cf6397
Transaction data is Public(PublicTransaction { message: Message { program_id: "d68109238654ce4c7af77ba2cdeb3f3d8eb3ea1fb563b9d5b15c0f081c3d6f40", account_ids: [EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7, Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP], nonces: [], instruction_data: [989106, 0, 0, 0] }, witness_set: WitnessSet { signatures_and_public_keys: [] } })
```

3. Initialize new public account and send funds.
```bash
# Initialize new Keycard public account.
wallet auth-transfer init --key-path "m/44'/60'/0'/0/1"

# Output:
Keycard PIN: # Enter Keycard pin
Transaction hash is a801bd61c0acc04917fb61e8e27673591df368ab0542c68a5cb1cf2272744d8e
Transaction data is Public(PublicTransaction { message: Message { program_id: "adbf67b01ded1e29c7a0b7b1b580e6ad4166a8fd52b57bf629fe78d4c779a48a", account_ids: [7ZMZuc3FgzHj3pSggGP1kbeZRCdwD8L4P8Wg9N2qsYcB], nonces: [Nonce(0)], instruction_data: [0, 0, 0, 0] }, witness_set: WitnessSet { signatures_and_public_keys: [(4470c76742e3a965fd07c5d5510a25a8e9b553f922df40ec5c4585e2b765e4c15056ee7485440b49762f92654bb7f4bba0565cbc7e70154ae475c990052cb830, 1c53c6a6c5e552fd739b3812f04381c0e502278fe851efea491cfd2f560cd25d)] } })
Stored persistent accounts at /home/mara/.nssa/wallet/storage.json

# Send native tokens from one account to the other.
wallet auth-transfer send --amount 40 \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to-key-path   "m/44'/60'/0'/0/1"

# Output:
Keycard PIN: # Enter Keycard pin
Transaction hash is 1a9764ab20763dcc1ffb51c6e9badd5a6316a773759032ca48e0eee59caaf488
Transaction data is Public(PublicTransaction { message: Message { program_id: "adbf67b01ded1e29c7a0b7b1b580e6ad4166a8fd52b57bf629fe78d4c779a48a", account_ids: [Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP, 7ZMZuc3FgzHj3pSggGP1kbeZRCdwD8L4P8Wg9N2qsYcB], nonces: [Nonce(1), Nonce(1)], instruction_data: [40, 0, 0, 0] }, witness_set: WitnessSet { signatures_and_public_keys: [(073fc99121c9d95de120b15057fdd922de2bb059db8382674f600cd2047aa97d1d2cad09becd8e05014a3704916f41e29eedf002649bffe7864f431a75d5f6a2, 0a5873812f910609da22d8aef918632677f3208faa3cec2b692f3e4c37ffd11d), (e6feaafd2de792be0f7f94312c3a97285e7b1f806388a0c10f7a5123a3d0389363fe35d0d56f1af21a0ead999a015d89479c004cc4dd33078efb17611b50b590, 1c53c6a6c5e552fd739b3812f04381c0e502278fe851efea491cfd2f560cd25d)] } })
```

4. Shielded transfer:
```bash
wallet auth-transfer send --amount 2 \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to-npk "55204e2934045b044f06d8222b454d46b54788f33c7dec4f6733d441703bb0e6" \
  --to-vpk "02a8626b0c0ad9383c5678dad48c3969b4174fb377cdb03a6259648032c774cec8"

# Output:
Keycard PIN: # Enter Keycard pin
Transaction hash is 8ad4b2dc5ab2c08bb6eefca6ec9b18151fa4452cd7e2a636c2fb158ecb46aef6
Stored persistent accounts at /home/mara/.nssa/wallet/storage.json
Shielded auth-transfer sent
```

### Account
| Command                | Description                                                         |
|------------------------|---------------------------------------------------------------------|
| `wallet account get`   | Get public account data given its ChainIndex (key path)              |

```bash
wallet account get --key-path "m/44'/60'/0'/0/0"

# Output:
Keycard PIN: # Enter Keycard pin
Account owned by authenticated transfer program
{"balance":108,"program_owner":"ChEp4BuCdGzJDHWoG1PTZLfZBbPxhYzstVMdakxym6bb","data":"","nonce":3}
```

### Token program
| Command                | Description                                                         |
|------------------------|---------------------------------------------------------------------|
| `wallet token new`     | ChainIndices (key paths) provided for definition and supply         |
| `wallet token init`    | ChaindIndex (key path) to initialize Keycard public account         |
| `wallet token send`    | ChainIndices (key paths) for `from` and `to` public accounts        |
| `wallet token burn`    | ChainIndex (key path) for holding account                           |
| `wallet token mint`    | ChainIndices (key paths) for definition and holding public accounts |

### AMM program
| Command                        | Description                                                         |
|--------------------------------|---------------------------------------------------------------------|
| `wallet amm new`               | ChainIndices (key paths) provided for definition and supply         |
| `wallet amm swap-exact-input`  | ChaindIndex (key path) to initialize Keycard public account         |
| `wallet amm swap-exact-output` | ChainIndices (key paths) for `from` and `to` public accounts        |
| `wallet amm add-liquidity`     | ChainIndex (key path) for holding account                           |
| `wallet amm reemove-liquidity` | ChainIndices (key paths) for definition and holding public accounts |