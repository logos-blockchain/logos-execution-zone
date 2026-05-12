This tutorial walks you through using Keycard with Wallet CLI. Keycard is optional hardware that can offer enhance security to a LEZ wallet. A LEZ wallet that utilizes Keycard does not store any secret keys for public accounts (eventually, this will extend to private accounts). Instead, Wallet CLI retrieves the appropriate public keys and signatures from Keycard.


## Keycard Setup

### Required hardware
- Keycard (Blank) - a Keycard, directly, from Keycard.tech cannot (currently) be updated to support LEE.
- Smartcard reader

### Firmware installation
Installation:

1. Install math applet on your keycard; this process only needs to be done once. In the root of repo:
    ```
    cd python/keycard_applets
    java -jar gp.jar --key c212e073ff8b4bbfaff4de8ab655221f --load math.cap
    ```
2. Install `keycard-desktop` from [github](https://github.com/choppu/keycard-desktop)
    - Keycard Desktop is used to install the LEE key protocol to a blank keycard.
    - Select (Re)Install Applet and upload the key binary (`python/keycard_applets/LEE_keycard.cap`).
    ![keycard-desktop.png](keycard-desktop.png)

## Wallet with Keycard
Keycard functionality is available to Wallet CLI by setting up the following Python virtual environment:

```bash
# Install appropriate version of `keycard-py`.
git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git python/keycard-py

# Set up virtual environment.
python3 -m venv venv
source venv/bin/activate
pip install pyscard mnemonic ecdsa pyaes
pip install -e python/keycard-py
```

**Important**: Keycard wallet commands only work within the virtual environment.
```bash
# In the root of LEE repo:
source venv/bin/activate
```

## Keycard Commands

### Keycard

| Command                           | Key-path options | Description                                                              |
|-----------------------------------|------------------|--------------------------------------------------------------------------|
| `wallet keycard available`        | —                | Checks whether a Keycard reader and card are accessible                  |
| `wallet keycard load`             | —                | Loads a mnemonic phrase onto the Keycard                                 |
| `wallet keycard get-private-keys` | `--key-path`     | Retrieves private account keys (nsk, vsk) for the given BIP32 path      |

1. Check keycard availability
```bash
wallet keycard available

# Output:
✅ Keycard is available.
```

2. Load a mnemonic phrase
```bash
wallet keycard load --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"

# Output:
Keycard PIN:
✅ Keycard is now connected to wallet.
```

3. Get private keys for a path
```bash
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/0"

# Output:
Keycard PIN:
nsk: 55e505bf925e536c843a12ebc08c41ca5f4761eeeb7fa33725f0b44e6f1ac2e4
vsk: 30f798893977a7b7263d1f77abf58e11e014428c92030d6a02fe363cceb41ffa
```

### Pinata (testnet)

| Command               | Key-path options              | Description                                                              |
|-----------------------|-------------------------------|--------------------------------------------------------------------------|
| `wallet pinata claim` | `--key-path`   | Claims a testnet pinata reward to a public or private recipient account  |

Note: The recipient account must be initialized with `wallet auth-transfer init` before claiming.

1. Claim to a Keycard public account
```bash
wallet pinata claim --key-path "m/44'/60'/0'/0/0"

# Output:
Keycard PIN:
Computing solution for pinata...
Found solution 989106 in 33.739525ms
Transaction hash is fd320c01f5469e62d2486afa1d9d5be39afcca0cd01d1575905b7acd95cf6397
```

2. Claim to a local wallet account by label
```bash
wallet pinata claim --to-label my-account

# Output:
Transaction hash is 2c8a4f1e903d5b76e80214c5b82e1d46a105e28930ad71bcce48f2d07b49a16f
```

### Authenticated-transfer program

| Command                     | Key-path options                     | Description                                                                        |
|-----------------------------|--------------------------------------|------------------------------------------------------------------------------------|
| `wallet auth-transfer init` | `--key-path`                         | Registers a public or private account with the auth-transfer program               |
| `wallet auth-transfer send` | `--from-key-path`, `--to-key-path`   | Sends native tokens; either or both endpoints can be Keycard public accounts       |

For `send`, `--from-key-path` and `--to-key-path` can be used together (both Keycard) or individually (one Keycard, one local/label). Shielded sends to foreign private accounts use `--to-npk`/`--to-vpk` instead of `--to-key-path`.

1. Initialize a Keycard public account
```bash
wallet auth-transfer init --key-path "m/44'/60'/0'/0/0"

# Output:
Keycard PIN:
Transaction hash is 49c16940493e1618c393645c1211b5c793d405838221c29ac6562a8a4b11c5a7
```

2. Send native tokens between two Keycard accounts
```bash
wallet auth-transfer send \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to-key-path   "m/44'/60'/0'/0/1" \
  --amount 40

# Output:
Keycard PIN:
Transaction hash is 1a9764ab20763dcc1ffb51c6e9badd5a6316a773759032ca48e0eee59caaf488
```

3. Send native tokens from Keycard to a local wallet account
```bash
# Note: non-keycard account ID below — replace with actual account ID or use --to-label
wallet auth-transfer send \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to            "Public/9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --amount 20

# Output:
Keycard PIN:
Transaction hash is 3e7b2a91cf804d56fe19084b3c8b25d07e8f243829bc50addf6e2c78b4b09d34
```