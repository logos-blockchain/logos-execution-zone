# Associated Token Accounts (ATAs)

This tutorial covers Associated Token Accounts (ATAs). An ATA lets you derive a unique token holding address from an owner account and a token definition — no need to create and track holding accounts manually. Given the same inputs, anyone can compute the same ATA address without a network call. By the end, you will have practiced:

1. Deriving ATA addresses locally.
2. Creating an ATA.
3. Sending tokens via ATAs.
4. Burning tokens from an ATA.
5. Listing ATAs across multiple token definitions.
6. Creating an ATA with a private owner.
7. Sending tokens from a private owner's ATA.
8. Burning tokens from a private owner's ATA.

> [!Important]
> This tutorial assumes you have completed the [wallet-setup](wallet-setup.md) and [custom-tokens](custom-tokens.md) tutorials. You need a running wallet with accounts and at least one token definition.

## Prerequisites

### Deploy the ATA program

Unlike the Token program (which is built-in), the ATA program must be deployed before you can use it. The pre-built binary is included in the repository:

```bash
wallet deploy-program artifacts/program_methods/associated_token_account.bin
```

> [!Note]
> Program deployment is idempotent — if the ATA program has already been deployed (e.g. by another user on the same network), the command is a no-op.

You can verify the deployment succeeded by running any `wallet ata` command. If the program is not deployed, commands that submit transactions will fail.

The CLI provides commands to work with the ATA program. Run `wallet ata` to see the options:

```bash
Commands:
  address  Derive and print the Associated Token Account address (local only, no network)
  create   Create (or idempotently no-op) the Associated Token Account
  send     Send tokens from owner's ATA to a recipient
  burn     Burn tokens from holder's ATA
  list     List all ATAs for a given owner across multiple token definitions
  help     Print this message or the help of the given subcommand(s)
```

## 1. How ATA addresses work

An ATA address is deterministically derived from two inputs:

1. The **owner** account ID.
2. The **token definition** account ID.

The derivation works as follows:

```
seed = SHA256(owner_id || definition_id)
ata_address = AccountId::from((ata_program_id, seed))
```

Because the computation is pure, anyone who knows the owner and definition can reproduce the exact same ATA address — no network call required.

> [!Note]
> All ATA commands that submit transactions accept a privacy prefix on the owner/holder argument — `Public/` for public accounts and `Private/` for private accounts. Using `Private/` generates a zero-knowledge proof locally and submits only the proof to the sequencer, keeping the owner's identity off-chain.

## 2. Deriving an ATA address (`wallet ata address`)

The `address` subcommand computes the ATA address locally without submitting a transaction.

### a. Set up an owner and token definition

If you already have a public account and a token definition from the custom-tokens tutorial, you can reuse them. Otherwise, create them now:

```bash
wallet account new public

# Output:
Generated new account with account_id Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB
```

```bash
wallet account new public

# Output:
Generated new account with account_id Public/3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4
```

```bash
wallet token new \
    --name MYTOKEN \
    --total-supply 10000 \
    --definition-account-id Public/3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4 \
    --supply-account-id Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB
```

### b. Derive the ATA address

```bash
wallet ata address \
    --owner 5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4

# Output:
7a2Bf9cKLm3XpRtH1wDqZs8vYjN4eU6gAoFxW5kMnE2R
```

> [!Note]
> This is a pure computation — no transaction is submitted and no network connection is needed. The same inputs will always produce the same output.

## 3. Creating an ATA (`wallet ata create`)

Before an ATA can hold tokens it must be created on-chain. The `create` subcommand submits a transaction that initializes the ATA. If it already exists, the operation is a no-op.

### a. Create the ATA

```bash
wallet ata create \
    --owner Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4
```

### b. Inspect the ATA

Use the ATA address derived in the previous section:

```bash
wallet account get --account-id Public/7a2Bf9cKLm3XpRtH1wDqZs8vYjN4eU6gAoFxW5kMnE2R

# Output:
Holding account owned by ata program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":0}
```

> [!Tip]
> Creation is idempotent — running the same command again is a no-op.

## 4. Sending tokens via ATA (`wallet ata send`)

The `send` subcommand transfers tokens from the owner's ATA to a recipient account.

### a. Fund the ATA

First, move tokens into the ATA from the supply account created earlier:

```bash
wallet token send \
    --from Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --to Public/7a2Bf9cKLm3XpRtH1wDqZs8vYjN4eU6gAoFxW5kMnE2R \
    --amount 5000
```

### b. Create a recipient account

```bash
wallet account new public

# Output:
Generated new account with account_id Public/9Ht4Kv8pYmW2rXjN6dFcQsA7bEoLf3gUZx1wDnR5eTi
```

### c. Send tokens from the ATA to the recipient

```bash
wallet ata send \
    --from Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4 \
    --to 9Ht4Kv8pYmW2rXjN6dFcQsA7bEoLf3gUZx1wDnR5eTi \
    --amount 2000
```

### d. Verify balances

```bash
wallet account get --account-id Public/7a2Bf9cKLm3XpRtH1wDqZs8vYjN4eU6gAoFxW5kMnE2R

# Output:
Holding account owned by ata program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":3000}
```

```bash
wallet account get --account-id Public/9Ht4Kv8pYmW2rXjN6dFcQsA7bEoLf3gUZx1wDnR5eTi

# Output:
Holding account owned by token program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":2000}
```

## 5. Burning tokens from an ATA (`wallet ata burn`)

The `burn` subcommand destroys tokens held in the owner's ATA, reducing the token's total supply.

### a. Burn tokens

```bash
wallet ata burn \
    --holder Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4 \
    --amount 500
```

### b. Verify the reduced balance

```bash
wallet account get --account-id Public/7a2Bf9cKLm3XpRtH1wDqZs8vYjN4eU6gAoFxW5kMnE2R

# Output:
Holding account owned by ata program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":2500}
```

## 6. Listing ATAs (`wallet ata list`)

The `list` subcommand queries ATAs for a given owner across one or more token definitions.

### a. Create a second token and ATA

Create a second token definition so there are multiple ATAs to list:

```bash
wallet account new public

# Output:
Generated new account with account_id Public/BxR3Lm7YkWp9vNs2hD4qJcTfA8eUoZ6gKn1wXjM5rFi
```

```bash
wallet account new public

# Output:
Generated new account with account_id Public/Ck8mVp4YhWn2rXjD6dFsQtA7bEoLf3gUZx1wDnR9eTs
```

```bash
wallet token new \
    --name OTHERTOKEN \
    --total-supply 5000 \
    --definition-account-id Public/BxR3Lm7YkWp9vNs2hD4qJcTfA8eUoZ6gKn1wXjM5rFi \
    --supply-account-id Public/Ck8mVp4YhWn2rXjD6dFsQtA7bEoLf3gUZx1wDnR9eTs
```

Create an ATA for the second token:

```bash
wallet ata create \
    --owner Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --token-definition BxR3Lm7YkWp9vNs2hD4qJcTfA8eUoZ6gKn1wXjM5rFi
```

### b. List ATAs for both token definitions

```bash
wallet ata list \
    --owner 5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --token-definition \
        3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4 \
        BxR3Lm7YkWp9vNs2hD4qJcTfA8eUoZ6gKn1wXjM5rFi

# Output:
ATA 7a2Bf9cKLm3XpRtH1wDqZs8vYjN4eU6gAoFxW5kMnE2R (definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4): balance 2500
ATA 4nPxKd8YmW7rVsH2jDfQcA9bEoLf6gUZx3wTnR1eMs5 (definition BxR3Lm7YkWp9vNs2hD4qJcTfA8eUoZ6gKn1wXjM5rFi): balance 0
```

> [!Note]
> The `list` command derives each ATA address locally and fetches its on-chain state. If an ATA has not been created for a given definition, it prints "No ATA for definition ..." instead.

## 7. Private owner operations

All three ATA operations — `create`, `send`, and `burn` — support private owner accounts. Passing a `Private/` prefix on the owner argument switches the wallet into privacy-preserving mode:

1. The wallet builds the transaction locally.
2. The ATA program is executed inside the RISC0 ZK VM to generate a proof.
3. The proof, the updated ATA state (in plaintext), and an encrypted update for the owner's private account are submitted to the sequencer.
4. The sequencer verifies the proof, writes the ATA state change to the public chain, and records the owner's new commitment in the nullifier set.

The result is that the ATA account and its token balance are **fully public** — anyone can see them. What stays private is the link between the ATA and its owner: the proof demonstrates that someone with the correct private key authorized the operation, but reveals nothing about which account that was.

> [!Note]
> The ATA address is derived from `SHA256(owner_id || definition_id)`. Because SHA256 is one-way, the ATA address does not reveal the owner's identity. However, if the owner's account ID becomes known for any other reason, all of their ATAs across every token definition can be enumerated by anyone.

### a. Create a private account

```bash
wallet account new private

# Output:
Generated new account with account_id Private/HkR7Lm2YnWp4vNs8hD3qJcTfA6eUoZ9gKn5wXjM1rFi
```

### b. Create the ATA for the private owner

Pass `Private/` on `--owner`. The token definition account has no privacy prefix — it is always a public account.

```bash
wallet ata create \
    --owner Private/HkR7Lm2YnWp4vNs8hD3qJcTfA6eUoZ9gKn5wXjM1rFi \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4
```

> [!Note]
> Proof generation runs locally in the RISC0 ZK VM and can take up to a minute on first run.

### c. Verify the ATA was created

Derive the ATA address using the raw account ID (no privacy prefix):

```bash
wallet ata address \
    --owner HkR7Lm2YnWp4vNs8hD3qJcTfA6eUoZ9gKn5wXjM1rFi \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4

# Output:
2pQxNf7YkWm3rVsH8jDcQaA4bEoLf9gUZx6wTnR2eMs1
```

```bash
wallet account get --account-id Public/2pQxNf7YkWm3rVsH8jDcQaA4bEoLf9gUZx6wTnR2eMs1

# Output:
Holding account owned by ata program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":0}
```

### d. Fund the ATA

The ATA is a public account. Fund it with a direct token transfer from any public holding account:

```bash
wallet token send \
    --from Public/5FkBei8HYoSUNqh9rWCrJDnSZE5FJfGiWmTvhgBx3qTB \
    --to Public/2pQxNf7YkWm3rVsH8jDcQaA4bEoLf9gUZx6wTnR2eMs1 \
    --amount 500
```

### e. Send tokens from the private owner's ATA

```bash
wallet ata send \
    --from Private/HkR7Lm2YnWp4vNs8hD3qJcTfA6eUoZ9gKn5wXjM1rFi \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4 \
    --to 9Ht4Kv8pYmW2rXjN6dFcQsA7bEoLf3gUZx1wDnR5eTi \
    --amount 200
```

Verify the ATA balance decreased:

```bash
wallet account get --account-id Public/2pQxNf7YkWm3rVsH8jDcQaA4bEoLf9gUZx6wTnR2eMs1

# Output:
Holding account owned by ata program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":300}
```

### f. Burn tokens from the private owner's ATA

```bash
wallet ata burn \
    --holder Private/HkR7Lm2YnWp4vNs8hD3qJcTfA6eUoZ9gKn5wXjM1rFi \
    --token-definition 3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4 \
    --amount 100
```

Verify the balance and token supply:

```bash
wallet account get --account-id Public/2pQxNf7YkWm3rVsH8jDcQaA4bEoLf9gUZx6wTnR2eMs1

# Output:
Holding account owned by ata program
{"account_type":"Token holding","definition_id":"3YpK8RvVzWm6Q4h2nDAbxJfLmuRqkEkFP9C7UwTdGvE4","balance":200}
```
