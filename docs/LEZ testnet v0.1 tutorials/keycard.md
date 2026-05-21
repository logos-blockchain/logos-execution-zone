This tutorial walks you through using Keycard with Wallet CLI. Keycard is optional hardware that can offer enhance security to a LEZ wallet. A LEZ wallet that utilizes Keycard does not store any secret keys for public accounts (eventually, this will extend to private accounts). Instead, Wallet CLI retrieves the appropriate public keys and signatures from Keycard.


## Keycard Setup

### Required hardware
- Keycard (Blank) - a Keycard, directly, from Keycard.tech cannot (currently) be updated to support LEE.
- Smartcard reader
- Applets (`math.cap` and `LEE_keycard.cap`). Eventually, both of these applets will be available in separate repos.
  - `math.cap` is an applet to speed up computations on Keycard; developed by Bitgamma (Keycard-tech team).
  - `LEE_keycard.cap` is an applet that contains LEE keycard protocol; developed by Bitgamma (Keycard-tech team)

### Firmware installation
Installation:

1. Install math applet on your keycard; this process only needs to be done once. In the root of repo:
    ```
    sudo apt-get install -y default-jdk
    wget https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v25.10.20/gp.jar -P keycard_wallet/keycard_applets
    cd keycard_wallet/keycard_applets
    java -jar gp.jar --key c212e073ff8b4bbfaff4de8ab655221f --load math.cap
    ```
2. Install `keycard-desktop` from [github](https://github.com/choppu/keycard-desktop)
    - Keycard Desktop is used to install the LEE key protocol to a blank keycard.
    - Select (Re)Install Applet and upload the key binary (`keycard_wallet/keycard_applets/LEE_keycard.cap`).
    ![keycard-desktop.png](keycard-desktop.png)
    - **Important:** keycard can only connect with one application at a time; if Keycard-Desktop is using keycard then Wallet CLI cannot access the same keycard, and vice-versa.

## Wallet with Keycard
Keycard functionality is available to Wallet CLI by setting up the following Python virtual environment. The steps below can also be run via `keycard_wallet/wallet_with_keycard.sh`.

```bash
# Install appropriate version of `keycard-py`.
git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git keycard_wallet/python/keycard-py

# Set up virtual environment.
python3 -m venv venv
source venv/bin/activate
pip install pyscard mnemonic ecdsa pyaes
pip install -e keycard_wallet/python/keycard-py
```

**Important**: Keycard wallet commands only work within the virtual environment.
```bash
# In the root of LEE repo:
source venv/bin/activate
```

## PIN entry

Each Keycard command prompts for a PIN interactively. To avoid re-entering it across multiple commands, export it as an environment variable:

```bash
export KEYCARD_PIN=123456
```

Unset it when done:

```bash
unset KEYCARD_PIN
```

## Keycard Commands

### Keycard

| Command                     | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `wallet keycard available`  | Checks whether a Keycard reader and card are accessible    |
| `wallet keycard init`       | Initializes a blank Keycard with a PIN and a generated PUK |
| `wallet keycard connect`    | Establishes and saves a pairing with the Keycard           |
| `wallet keycard disconnect` | Unpairs the Keycard and clears the saved pairing           |
| `wallet keycard load`       | Loads a mnemonic phrase onto the Keycard                   |

1. Check keycard availability
```bash
wallet keycard available

# Output:
✅ Keycard is available.
```

2. Initialize a blank Keycard
```bash
wallet keycard init

# Output:
Keycard PIN:
Keycard PUK: 847302916485
Record this PUK and store it somewhere safe. It cannot be recovered.
✅ Keycard initialized successfully.
```

3. Connect (pair and save pairing for subsequent commands)
```bash
wallet keycard connect

# Output:
Keycard PIN:
✅ Keycard paired and ready.
```

4. Load a mnemonic phrase
```bash
# Supply mnemonic via environment variable to avoid interactive prompt
export KEYCARD_MNEMONIC="fashion degree mountain wool question damp current pond grow dolphin chronic then"
wallet keycard load
unset KEYCARD_MNEMONIC

# Output:
Keycard PIN:
✅ Keycard is now connected to wallet.
✅ Mnemonic phrase loaded successfully.
```

5. Disconnect (unpair and clear saved pairing)
```bash
wallet keycard disconnect

# Output:
Keycard PIN:
✅ Keycard unpaired and pairing cleared.
```

### Pinata (testnet)

| Command               | Description                                                              |
|-----------------------|--------------------------------------------------------------------------|
| `wallet pinata claim` | Claims a testnet pinata reward to a public or private recipient account  |

Note: The recipient account must be initialized with `wallet auth-transfer init` before claiming.

`--to` accepts any of:
- A BIP32 key path — uses Keycard (e.g. `m/44'/60'/0'/0/0`)
- An account ID with privacy prefix (e.g. `Public/9bKm...`)
- An account label (e.g. `my-account`)

1. Claim to a Keycard public account
```bash
wallet pinata claim --to "m/44'/60'/0'/0/0"

# Output:
Keycard PIN:
Computing solution for pinata...
Found solution 989106 in 33.739525ms
Transaction hash is fd320c01f5469e62d2486afa1d9d5be39afcca0cd01d1575905b7acd95cf6397
```

2. Claim to a local wallet account by label
```bash
wallet pinata claim --to my-account

# Output:
Transaction hash is 2c8a4f1e903d5b76e80214c5b82e1d46a105e28930ad71bcce48f2d07b49a16f
```

### Authenticated-transfer program

| Command                     | Description                                                                   |
|-----------------------------|-------------------------------------------------------------------------------|
| `wallet auth-transfer init` | Registers an account with the auth-transfer program                           |
| `wallet auth-transfer send` | Sends native tokens between accounts                                          |

`--account-id` (for `init`) and `--from`/`--to` (for `send`) each accept any of:
- A BIP32 key path — uses Keycard (e.g. `m/44'/60'/0'/0/0`)
- An account ID with privacy prefix (e.g. `Public/9bKm...`)
- An account label (e.g. `my-account`)

For `send`, foreign recipient accounts (not in the local wallet and not a Keycard path) do not need to sign — pass their account ID directly via `--to`. Shielded sends to foreign private accounts use `--to-npk`/`--to-vpk`.

1. Initialize a Keycard public account
```bash
wallet auth-transfer init --account-id "m/44'/60'/0'/0/0"

# Output:
Keycard PIN:
Transaction hash is 49c16940493e1618c393645c1211b5c793d405838221c29ac6562a8a4b11c5a7
```

2. Send native tokens between two Keycard accounts
```bash
wallet auth-transfer send \
  --from   "m/44'/60'/0'/0/0" \
  --to     "m/44'/60'/0'/0/1" \
  --amount 40

# Output:
Keycard PIN:
Transaction hash is 1a9764ab20763dcc1ffb51c6e9badd5a6316a773759032ca48e0eee59caaf488
```

3. Send native tokens from a Keycard account to a foreign account
```bash
wallet auth-transfer send \
  --from   "m/44'/60'/0'/0/0" \
  --to     "Public/9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --amount 20

# Output:
Keycard PIN:
Transaction hash is 3e7b2a91cf804d56fe19084b3c8b25d07e8f243829bc50addf6e2c78b4b09d34
```

4. Send native tokens from a Keycard account to a local wallet account by label
```bash
wallet auth-transfer send \
  --from   "m/44'/60'/0'/0/0" \
  --to     my-account \
  --amount 20

# Output:
Keycard PIN:
Transaction hash is 7d4c1b8e2f903a56fd19084b3c8b25d07e8f243829bc50addf6e2c78b4b09e45
```

## Testing

Tests for Keycard commands are in `keycard_wallet/tests/keycard_tests.sh`. Run from the repo root with a Keycard connected:

```bash
bash keycard_wallet/tests/keycard_tests.sh
```

## SigningGroups

`SigningGroups` (`wallet/src/signing.rs`) partitions a transaction's signers into two buckets — local accounts and Keycard accounts. This ensures that Python GIL is only used at most once per transaction, regardless of how many Keycard accounts are involved.

Local signers are resolved and signed in pure Rust. Keycard signers store only their BIP32 key path; all of them are signed inside a single Python session (`connect` / `close_session`) when `sign_all` is called. The command calls `needs_pin` to decide whether to prompt for a PIN before signing.

Foreign recipient accounts — those with no local key and no Keycard path — are silently skipped and require neither a signature nor a nonce.

```
SigningGroups {
    local:   [(AccountId, PrivateKey)],   // signed in pure Rust
    keycard: [(AccountId, BIP32Path)],    // signed via a single Python/Keycard session
}
```