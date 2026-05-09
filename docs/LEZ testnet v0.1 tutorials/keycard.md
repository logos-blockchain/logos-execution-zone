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

4. Shielded send from Keycard to a foreign private account
```bash
wallet auth-transfer send \
  --from-key-path "m/44'/60'/0'/0/0" \
  --to-npk "55204e2934045b044f06d8222b454d46b54788f33c7dec4f6733d441703bb0e6" \
  --to-vpk "02a8626b0c0ad9383c5678dad48c3969b4174fb377cdb03a6259648032c774cec8" \
  --amount 2

# Output:
Keycard PIN:
Transaction hash is 8ad4b2dc5ab2c08bb6eefca6ec9b18151fa4452cd7e2a636c2fb158ecb46aef6
```

### Account

| Command                      | Key-path options | Description                                                               |
|------------------------------|------------------|---------------------------------------------------------------------------|
| `wallet account get`         | `--key-path`     | Retrieves on-chain account data; accepts a Keycard path, label, or ID    |
| `wallet account id`          | `--key-path`     | Prints the raw account ID for a Keycard path (useful for shell scripting) |

1. Get account state by Keycard path
```bash
wallet account get --key-path "m/44'/60'/0'/0/0"

# Output:
Keycard PIN:
Account owned by authenticated transfer program
{"balance":108,"program_owner":"ChEp4BuCdGzJDHWoG1PTZLfZBbPxhYzstVMdakxym6bb","data":"","nonce":3}
```

2. Print raw account ID for shell scripting
```bash
LEZ_DEF=$(wallet account id --key-path "m/44'/60'/0'/0/0")

# Output:
Keycard PIN:
# Prints: Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP
```

### Token program
| Command                | Key-path options                                                          | Description                                                            |
|------------------------|---------------------------------------------------------------------------|------------------------------------------------------------------------|
| `wallet token new`     | `--definition-key-path`, `--supply-key-path`                              | Creates a new token; Keycard signs for definition and supply accounts  |
| `wallet token init`    | `--holder-key-path`                                                       | Initializes a token holding for a Keycard public account               |
| `wallet token send`    | `--from-key-path`, `--to-key-path`                                        | Transfers tokens between accounts; either endpoint can be Keycard      |
| `wallet token burn`    | `--holder-key-path`                                                       | Burns tokens from a Keycard holding account                            |
| `wallet token mint`    | `--definition-key-path`, `--holder-key-path`                              | Mints tokens; Keycard signs for definition and/or holding account      |

These commands work as expected, but use `--key-path` options to sign with a Keycard public account instead of a local wallet account.

1. Create new token
```bash
wallet token new \
  --definition-key-path "m/44'/60'/0'/0/0" \
  --supply-key-path     "m/44'/60'/0'/0/1" \
  --name SNT \
  --total-supply 100000

# Output:
Keycard PIN:
Transaction hash is 2f0ddd9ad46e1c8cde8dac4eb69ebb5d8fdf167647e421aa79900adaaa9b34d0
```

2. Initialize token holding
```bash
# Note: --definition-account-id uses a non-keycard account ID — replace with actual definition ID
wallet token init \
  --definition-account-id "Public/9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --holder-key-path "m/44'/60'/0'/0/2"

# Output:
Keycard PIN:
Transaction hash is d4442e32bf33efbac03672e3c5f6e181bc7e34f0911cf00ef915eeaee6787a5b
```

3. Transfer tokens
```bash
# Send from a Keycard account to a local wallet account (--to-label) or another Keycard account (--to-key-path)
wallet token send \
  --from-key-path "m/44'/60'/0'/0/1" \
  --to-key-path   "m/44'/60'/0'/0/2" \
  --amount 1000

# Output:
Keycard PIN:
Transaction hash is cf1db3733c93c72b7a7c416403b558dbebcaf072f1797b09c2708f6dbc1ee58a
```

4. Mint tokens
```bash
wallet token mint \
  --definition-key-path "m/44'/60'/0'/0/0" \
  --holder-key-path     "m/44'/60'/0'/0/2" \
  --amount 5000

# Output:
Keycard PIN:
Transaction hash is 3a8f1b2e9c4d07a5fe6082b3d91c5e74f28160a7bc43091dde57f6a8b2c9e51f
```

5. Burn tokens
```bash
# Note: --definition uses a non-keycard account ID — replace with actual definition ID
wallet token burn \
  --definition      "Public/9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --holder-key-path "m/44'/60'/0'/0/2" \
  --amount 500

# Output:
Keycard PIN:
Transaction hash is 7e4c2a91bf803d56fe19074b3c8a25d06e7f143829bc50addf6e1c78a4b09d23
```

### ATA program
The Associated Token Account (ATA) program creates deterministic token holding accounts derived from an owner account and a token definition. All write operations accept `--key-path` (or `--from-key-path`) to sign with a Keycard account instead of a local wallet account.

| Command               | Key-path options    | Description                                                                  |
|-----------------------|---------------------|------------------------------------------------------------------------------|
| `wallet ata create`   | `--key-path`        | Creates (or idempotently no-ops) the ATA for the given owner + token pair    |
| `wallet ata send`     | `--from-key-path`   | Transfers tokens from the owner's ATA to a recipient token holding account   |
| `wallet ata burn`     | `--key-path`        | Burns tokens from the holder's ATA                                           |

1. Derive ATA address (local, no signing)
```bash
# Note: --owner and --token-definition take raw account IDs without a privacy prefix
# Note: non-keycard account ID below — replace with actual owner/definition IDs
wallet ata address \
  --owner            "9bKmZ4n7PqVRxEtY3dWsQjA2cHrFT5LpDoGXM8wJuNv6" \
  --token-definition "J9kXbdnzbZtH31RbZPxwky9bWbw3Tzr5jcfGbzkMwNUy"

# Output:
# Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP
```

2. Create ATA (Keycard owner)
```bash
# Note: --token-definition takes a raw account ID without a privacy prefix
wallet ata create \
  --key-path         "m/44'/60'/0'/0/7" \
  --token-definition "J9kXbdnzbZtH31RbZPxwky9bWbw3Tzr5jcfGbzkMwNUy"

# Output:
Keycard PIN:
Transaction hash is 5e1f3b8a2c094d67fe802945c3b71e50a016e28931bc04addf7e3c89b1a05f73
```

3. Send tokens from Keycard owner's ATA
```bash
# --from-key-path resolves the sender owner; --to is the recipient token holding (raw ID, no prefix)
# Note: --to value below is a non-keycard account ID — replace with the actual recipient holding ID
wallet ata send \
  --from-key-path    "m/44'/60'/0'/0/7" \
  --token-definition "J9kXbdnzbZtH31RbZPxwky9bWbw3Tzr5jcfGbzkMwNUy" \
  --to               "Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP" \
  --amount           500

# Output:
Keycard PIN:
Transaction hash is 9d2a7e41b03c8f56970b5e38d15c7a83e126f39821bc05addf7e2c98d1b14f61
```

4. Burn tokens from Keycard owner's ATA
```bash
wallet ata burn \
  --key-path         "m/44'/60'/0'/0/7" \
  --token-definition "J9kXbdnzbZtH31RbZPxwky9bWbw3Tzr5jcfGbzkMwNUy" \
  --amount           200

# Output:
Keycard PIN:
Transaction hash is 2c5e9a72b08d4f67830b4e19d25c7b83f026e48931bc05ddaf7e3d89c1a04f92
```

### AMM program
| Command                        | Key-path options                                                                    | Description                                                                 |
|--------------------------------|-------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `wallet amm new`               | `--user-holding-a-key-path`, `--user-holding-b-key-path`                            | Creates a new AMM pool; LP holding must be a local wallet account           |
| `wallet amm swap-exact-input`  | `--user-holding-a-key-path`, `--user-holding-b-key-path`                            | Swaps tokens; only the seller's key path is required for signing            |
| `wallet amm swap-exact-output` | `--user-holding-a-key-path`, `--user-holding-b-key-path`                            | Swaps tokens specifying exact output; only the seller's key path is required|
| `wallet amm add-liquidity`     | `--user-holding-a-key-path`, `--user-holding-b-key-path`, `--user-holding-lp-key-path` | Adds liquidity to a pool using Keycard accounts                          |
| `wallet amm remove-liquidity`  | `--user-holding-a-key-path`, `--user-holding-b-key-path`, `--user-holding-lp-key-path` | Removes liquidity from a pool using Keycard accounts                     |

These commands use `--key-path` options to sign with Keycard public accounts. For `wallet amm new`, the LP holding account must be a local wallet account (Keycard is not supported for the LP recipient in pool creation).

1. Create AMM pool
```bash
# Note: --user-holding-a-label and --user-holding-b-label use non-keycard wallet accounts — replace with actual labels or --user-holding-a/b-key-path for Keycard holdings
wallet amm new \
  --user-holding-a-label my-lez-fund \
  --user-holding-b-label my-lee-fund \
  --user-holding-lp-label my-lp-fund \
  --balance-a 10000 \
  --balance-b 10000

# Output:
Transaction hash is abce4e4c771aab36107a0c590114d5ce597453602b8216a88d9164e7f7fd7854
```

2. Swap exact input (sell token B, receive token A)
```bash
# Provide key paths for both holdings; only the seller's path is used for signing
wallet amm swap-exact-input \
  --user-holding-a-key-path "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path "m/44'/60'/0'/0/5" \
  --amount-in      500 \
  --min-amount-out 1 \
  --token-definition "J9kXbdnzbZtH31RbZPxwky9bWbw3Tzr5jcfGbzkMwNUy"

# Output:
Keycard PIN:
Transaction hash is 280d549ce3046dd5dc6e985076ffb3681f0196572eeac996473ca6cc5be070be
```

3. Swap exact output (buy token A, sell token B)
```bash
wallet amm swap-exact-output \
  --user-holding-a-key-path "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path "m/44'/60'/0'/0/5" \
  --exact-amount-out 400 \
  --max-amount-in    600 \
  --token-definition "Fh8d1HsqEUDzwg1vc1E9123nRpEGHJwwdqtiWu73JHPP"

# Output:
Keycard PIN:
Transaction hash is 1f7a3c5e9d82b04610fe2875c3a91b6d408e53f2bc7409adde16f0c78b2e4d9a
```

4. Add liquidity
```bash
wallet amm add-liquidity \
  --user-holding-a-key-path  "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path  "m/44'/60'/0'/0/5" \
  --user-holding-lp-key-path "m/44'/60'/0'/0/6" \
  --max-amount-a  1000 \
  --max-amount-b  1000 \
  --min-amount-lp 1

# Output:
Keycard PIN:
Transaction hash is 4b8e2d71a09c3f56870b4e29d15c7a83e026f48931bc05addf7e2d89c1b04f72
```

5. Remove liquidity
```bash
wallet amm remove-liquidity \
  --user-holding-a-key-path  "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path  "m/44'/60'/0'/0/5" \
  --user-holding-lp-key-path "m/44'/60'/0'/0/6" \
  --balance-lp   500 \
  --min-amount-a 1 \
  --min-amount-b 1

# Output:
Keycard PIN:
Transaction hash is 8c4f1a93e27b065d3f9084c5b72e1d46a015e38920ad71bcce48f3d07b59a26e
```