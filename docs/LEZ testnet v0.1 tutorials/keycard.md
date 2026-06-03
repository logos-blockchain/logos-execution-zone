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
    wget https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v25.10.20/gp.jar -P lez/keycard_wallet/keycard_applets
    cd lez/keycard_wallet/keycard_applets
    java -jar gp.jar --key c212e073ff8b4bbfaff4de8ab655221f --load math.cap
    ```
2. Install `keycard-desktop` from [github](https://github.com/choppu/keycard-desktop)
    - Keycard Desktop is used to install the LEE key protocol to a blank keycard.
    - Select (Re)Install Applet and upload the key binary (`lez/keycard_wallet/keycard_applets/LEE_keycard.cap`).
    ![keycard-desktop.png](keycard-desktop.png)
    - **Important:** keycard can only connect with one application at a time; if Keycard-Desktop is using keycard then Wallet CLI cannot access the same keycard, and vice-versa.

## Wallet with Keycard
Keycard functionality is available to Wallet CLI by setting up the following Python virtual environment. The steps below can also be run via `lez/keycard_wallet/wallet_with_keycard.sh`.

```bash
# Install appropriate version of `keycard-py`.
git clone --branch lee-schnorr --single-branch https://github.com/bitgamma/keycard-py.git lez/keycard_wallet/python/keycard-py

# Set up virtual environment.
python3 -m venv venv
source venv/bin/activate
pip install pyscard mnemonic ecdsa pyaes
pip install -e lez/keycard_wallet/python/keycard-py
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

## Pairing password

The pairing password is used to establish a secure channel between the wallet and the card. It is set permanently on the card during `wallet keycard init` and must match on every subsequent re-pair.

The default password (`KeycardDefaultPairing`) is [recommended](https://docs.keycard.tech/en/developers/core) for most users. Wallet CLI allows advance users the flexibility to set their own pairing password.

To use a custom pairing password, set it before `init`:

```bash
# Note: Keep the leading space before this command.
# Leading space prevents this command from being stored in shell history
# (when HISTCONTROL=ignorespace is enabled).
 export KEYCARD_PAIRING_PASSWORD=my-custom-password
wallet keycard init
```

After a successful initializaation, subsequent commands (`connect`, transfers) use the cached pairing index and key — the pairing password is not needed again until the pairing is cleared.

**Important:** if you initialized with a custom password, `KEYCARD_PAIRING_PASSWORD` must be set in every session where re-pairing can occur (after `disconnect`, or on a new machine). If the env var is missing then wallet CLI will attempt to use the default password. As a result, pairing will fail.

Unset the pairing password variable when done:

```bash
unset KEYCARD_PAIRING_PASSWORD
```

## Keycard Commands

### Keycard

| Command                          | Description                                                           |
|----------------------------------|-----------------------------------------------------------------------|
| `wallet keycard available`       | Checks whether a Keycard reader and card are accessible               |
| `wallet keycard init`            | Initializes a blank Keycard with a PIN and a generated PUK            |
| `wallet keycard connect`         | Establishes and saves a pairing with the Keycard                      |
| `wallet keycard disconnect`      | Unpairs the Keycard and clears the saved pairing                      |
| `wallet keycard load`            | Loads a mnemonic phrase onto the Keycard                              |
| `wallet keycard get-private-keys`| Prints NSK and VSK for a BIP-32 path — **debug builds only** (see below) |

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

6. Get private keys for a BIP-32 path (**debug builds only**)

`get-private-keys` exports the raw NSK and VSK for a derivation path. NSK gates nullifier creation and VSK gates note decryption — either key is sufficient to fully compromise that account's privacy. The command is only available in debug builds and requires `--reveal` to confirm intent.

First install the wallet with the `keycard-debug` feature:
```bash
cargo install --path lez/wallet --force --features keycard-debug
```

Then run the command:
```bash
wallet keycard get-private-keys --key-path "m/44'/60'/0'/0/0" --reveal

# Output:
WARNING: NSK and VSK are being printed to stdout. Any terminal log, scrollback, or screen recording captures these keys.
Keycard PIN:
NSK: 55e505bf925e536c843a12ebc08c41ca5f4761eeeb7fa33725f0b44e6f1ac2e4
VSK: 30f798893977a7b7263d1f77abf58e11e014428c92030d6a02fe363cceb41ffa
```

To restore the standard build without `keycard-debug` afterwards:
```bash
cargo install --path lez/wallet --force
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

### Token program

`--definition`, `--holder`, `--from`, and `--to` each accept any of:
- A BIP-32 key path — uses Keycard (e.g. `m/44'/60'/0'/0/0`)
- An account ID with privacy prefix (e.g. `Public/9bKm...`)
- An account label (e.g. `my-account`)

The token program requires both the definition account and the holder/recipient to sign when both are owned. If only one is a Keycard path, only that account signs via the card; the other signs locally or is treated as foreign.

**Shielded transfers** (public Keycard sender → private recipient) are supported. The Keycard signs the public sender's authorization; the ZK circuit handles the private recipient side.

| Command            | Description                                           |
|--------------------|-------------------------------------------------------|
| `wallet token new` | Creates a new token definition with an initial supply |
| `wallet token send`| Transfers tokens between accounts                     |
| `wallet token mint`| Mints tokens to a holder account                      |
| `wallet token burn`| Burns tokens from a holder account                    |

1. Create a new token — definition and supply both on Keycard
```bash
wallet token new \
  --definition-account-id "m/44'/60'/0'/0/2" \
  --supply-account-id     "m/44'/60'/0'/0/3" \
  --name LEZ \
  --total-supply 100000

# Output:
Keycard PIN:
Transaction hash is a3f1c8e2049b7d56fe19084b3c8b25d07e8f243829bc50addf6e2c78b4b09d11
Transaction data is ...
```

2. Transfer tokens between two Keycard accounts (public → public)
```bash
wallet token send \
  --from   "m/44'/60'/0'/0/3" \
  --to     "m/44'/60'/0'/0/6" \
  --amount 20000

# Output:
Keycard PIN:
Transaction hash is b2e4d9f1038c6e45ad28175c4d9c36e18bf9354930cd61beef59f3e89c5a0e22
Transaction data is ...
```

3. Transfer tokens from a Keycard account to a private account (shielded)
```bash
wallet token send \
  --from   "m/44'/60'/0'/0/6" \
  --to     "Private/CJwKfrb3DFMmFvujQSB5ARcRTAa8EdP6eWm2hmSkF7Rb" \
  --amount 500

# Output:
Keycard PIN:
Transaction hash is c5f7e0a2149d8f67be39286d5eaa47f29cg0465041de72cff06a4f9ad6b1f33
```

4. Mint tokens — Keycard definition account mints to a Keycard holder
```bash
wallet token mint \
  --definition "m/44'/60'/0'/0/2" \
  --holder     "m/44'/60'/0'/0/6" \
  --amount 2000

# Output:
Keycard PIN:
Transaction hash is d6g8f1b3250e9a78cf4a397e6fbb58g3ah1567152ef83dgg17b5g0be7c2g0g44
Transaction data is ...
```

5. Burn tokens — Keycard holder burns from its own account
```bash
wallet token burn \
  --definition "Public/9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --holder     "m/44'/60'/0'/0/6" \
  --amount 500

# Output:
Keycard PIN:
Transaction hash is e7h9g2c4361f0b89dg5b408f7gcc69h4bi2678263fg94ehh28c6h1cf8d3h1h55
Transaction data is ...
```

### AMM program

AMM operations are **public only** — all holdings involved must be public accounts. Keycard accounts can be used for any or all of the holding accounts.

`--user-holding-a`, `--user-holding-b`, and `--user-holding-lp` each accept any of:
- A BIP-32 key path — uses Keycard (e.g. `m/44'/60'/0'/0/0`)
- An account ID with privacy prefix (e.g. `Public/9bKm...`)
- An account label (e.g. `my-account`)

For swaps, only the seller's holding signs — the wallet identifies which holding corresponds to the input token and signs only that account.

| Command                    | Description                                           |
|----------------------------|-------------------------------------------------------|
| `wallet amm new`           | Creates a new AMM liquidity pool                      |
| `wallet amm swap-exact-input`  | Swaps specifying exact input amount               |
| `wallet amm swap-exact-output` | Swaps specifying exact output amount              |
| `wallet amm add-liquidity` | Adds liquidity to an existing pool                    |
| `wallet amm remove-liquidity` | Removes liquidity from a pool                      |

1. Create a new AMM pool — all holdings on Keycard
```bash
wallet amm new \
  --user-holding-a  "m/44'/60'/0'/0/6" \
  --user-holding-b  "m/44'/60'/0'/0/7" \
  --user-holding-lp "m/44'/60'/0'/0/8" \
  --balance-a 10000 \
  --balance-b 10000

# Output:
Keycard PIN:
Transaction hash is f8i0h3d5472g1c90eh6c519g8hdd70i5cj3789374gh05fii39d7i2dg9e4i2i66
Transaction data is ...
```

2. Swap exact input — Keycard account sells LEE, receives LEZ
```bash
wallet amm swap-exact-input \
  --user-holding-a  "m/44'/60'/0'/0/6" \
  --user-holding-b  "m/44'/60'/0'/0/7" \
  --amount-in       500 \
  --min-amount-out  1 \
  --token-definition "9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6"

# Output:
Keycard PIN:
Transaction hash is g9j1i4e6583h2d01fi7d620h9iee81j6dk4890485hi16gjj40e8j3eh0f5j3j77
Transaction data is ...
```

3. Add liquidity — all three holdings on Keycard
```bash
wallet amm add-liquidity \
  --user-holding-a  "m/44'/60'/0'/0/6" \
  --user-holding-b  "m/44'/60'/0'/0/7" \
  --user-holding-lp "m/44'/60'/0'/0/8" \
  --max-amount-a  1000 \
  --max-amount-b  1000 \
  --min-amount-lp 1

# Output:
Keycard PIN:
Transaction hash is h0k2j5f7694i3e12gj8e731i0jff92k7el5901596ij27hkk51f9k4fi1g6k4k88
Transaction data is ...
```

4. Remove liquidity — LP holding on Keycard
```bash
wallet amm remove-liquidity \
  --user-holding-a  "m/44'/60'/0'/0/6" \
  --user-holding-b  "m/44'/60'/0'/0/7" \
  --user-holding-lp "m/44'/60'/0'/0/8" \
  --balance-lp   500 \
  --min-amount-a 1 \
  --min-amount-b 1

# Output:
Keycard PIN:
Transaction hash is i1l3k6g8705j4f23hk9f842j1kgg03l8fm6012607jk38ill62g0l5gj2h7l5l99
Transaction data is ...
```

### ATA program

The Associated Token Account program derives a deterministic token holding address from an owner account and a token definition. Keycard accounts can be used as the owner.

`--owner` and `--from`/`--holder` accept any of:
- A BIP-32 key path — uses Keycard (e.g. `m/44'/60'/0'/0/0`)
- An account ID with privacy prefix (e.g. `Public/9bKm...`)
- An account label (e.g. `my-account`)

| Command            | Description                                                      |
|--------------------|------------------------------------------------------------------|
| `wallet ata address` | Derives and prints the ATA address (local only, no network)   |
| `wallet ata create`  | Creates the ATA on-chain                                       |
| `wallet ata send`    | Sends tokens from the owner's ATA to a recipient               |
| `wallet ata burn`    | Burns tokens from the owner's ATA                              |
| `wallet ata list`    | Lists ATAs for a given owner across token definitions          |

1. Derive an ATA address for a Keycard account
```bash
# First resolve the Keycard account ID
OWNER_ID=$(wallet account id --account-id "m/44'/60'/0'/0/9")
wallet ata address \
  --owner            "$OWNER_ID" \
  --token-definition "9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6"

# Output:
DFMmFvujQSB5ARcRTAa8EdP6eWm2hmSkF7RbCJwKfrb3
```

2. Create an ATA — Keycard account as owner
```bash
wallet ata create \
  --owner            "m/44'/60'/0'/0/9" \
  --token-definition "9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6"

# Output:
Keycard PIN:
Transaction hash is j2m4l7h9816k5g34il0g953k2lhh14m9gn7123718kl49jmm73h1m6hk3i8m6m00
Transaction data is ...
```

3. Send tokens from a Keycard ATA to another account
```bash
wallet ata send \
  --from             "m/44'/60'/0'/0/9" \
  --token-definition "9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --to               "DFMmFvujQSB5ARcRTAa8EdP6eWm2hmSkF7RbCJwKfrb3" \
  --amount           500

# Output:
Keycard PIN:
Transaction hash is k3n5m8i0927l6h45jm1h064l3mii25n0ho8234829lm50knn84i2n7il4j9n7n11
Transaction data is ...
```

4. Burn tokens from a Keycard ATA
```bash
wallet ata burn \
  --holder           "m/44'/60'/0'/0/9" \
  --token-definition "9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --amount           200

# Output:
Keycard PIN:
Transaction hash is l4o6n9j1038m7i56kn2i175m4njj36o1ip9345930mn61loo95j3o8jm5k0o8o22
Transaction data is ...
```

## Testing

Tests for Keycard commands are in `lez/keycard_wallet/tests/`.

| Test file | Description |
|---|---|
| `keycard_tests.sh` | Core Keycard wallet commands and `auth-transfer` commands |
| `keycard_tests_2.sh` | Tests Keycard wallet commands for `amma`, `token` and `ata` programs |
| `keycard_test_3.sh` |  Demonstrates retrieving private account keys from keycard |
| `keycard_power_recovery_tests.sh` | Modified test file of `keycard_tests.sh` to test power recovery paths |

Run from the repo root with a Keycard connected:

```bash
bash lez/keycard_wallet/tests/keycard_tests.sh
bash lez/keycard_wallet/tests/keycard_tests_2.sh
bash lez/keycard_wallet/tests/keycard_test_3.sh
bash lez/keycard_wallet/tests/keycard_power_recovery_tests.sh
```

## SigningGroup

`SigningGroup` (`lez/wallet/src/signing.rs`) partitions a transaction's signers into two buckets — local accounts and Keycard accounts. This ensures that Python GIL is only used at most once per transaction, regardless of how many Keycard accounts are involved.

Local signers are resolved and signed in pure Rust. Keycard signers store only their BIP32 key path; all of them are signed inside a single Python session (`connect` / `close_session`) when `sign_all` is called. The command calls `needs_pin` to decide whether to prompt for a PIN before signing.

Foreign recipient accounts — those with no local key and no Keycard path — are silently skipped and require neither a signature nor a nonce.

```
SigningGroup {
    local:   [(AccountId, PrivateKey)],   // signed in pure Rust
    keycard: [(AccountId, BIP32Path)],    // signed via a single Python/Keycard session
}
```
```