This tutorial walks through native token transfers between public and private accounts using the Authenticated-Transfers program. You will create and initialize accounts, fund them with the Pinata program, and run transfers across different privacy combinations. By the end, you will have practiced:
1. Public account creation and initialization.
2. Account funding through the Pinata program.
3. Native token transfers between public accounts.
4. Private account creation.
5. Native token transfer from a public account to a private account.
6. Native token transfer from a public account to a private account owned by someone else.
7. Sending to a private accounts key from multiple independent senders.

---

The CLI provides commands to manage accounts. Run `wallet account` to see the options available:
```bash
Commands:
  get           Get account data
  new           Produce new public or private account
  sync-private  Sync private accounts
  help  Print this message or the help of the given subcommand(s)
```

## 1. Public account creation and initialization
> [!Important]
> Public accounts live on-chain and are identified by a 32-byte Account ID. Running `wallet account new public` generates a fresh keypair for the signature scheme used in LEZ.
> The account ID is derived from the public key, and the private key signs transactions and authorizes program executions.
> The CLI can create both public and private accounts.

### a. New public account creation
```bash
wallet account new public

# Output:
Generated new account with account_id Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ
```
> [!Tip]
> Save this account ID. You will use it in later commands.

### b. Account initialization

To query the account’s current status, run:

```bash
# Replace the id with yours
wallet account get --account-id Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ

# Output:
Account is Uninitialized
```

In this example, we initialize the account for the authenticated-transfer program, which manages native token transfers and enforces authenticated debits.

1. Initialize the account:
```bash
# This command submits a public transaction executing the `init` function of the
# authenticated-transfer program. The wallet polls the sequencer until the
# transaction is included in a block, which may take several seconds.
wallet auth-transfer init --account-id Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ
```

2. Check the updated account status:
```bash
wallet account get --account-id Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ

# Output:
Account owned by authenticated-transfer program
{"balance":0}
```

> [!NOTE]
> New accounts start uninitialized, meaning no program owns them yet. Any program may claim an uninitialized account; once claimed, that program owns it.
> Owned accounts can only be modified through executions of the owning program. The only exception is native-token credits: any program may credit native tokens to any account.
> Debiting native tokens must always be performed by the owning program.

## 2. Account funding through the Piñata program
Now that the account is initialized under the authenticated-tansfer program, fund it using the testnet Piñata program.

```bash
# Replace with your id
wallet pinata claim --to Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ
```

After the claim succeeds, the account is funded:

```bash
wallet account get --account-id Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ

# Output:
Account owned by authenticated-transfer program
{"balance":150}
```

## 3. Native token transfers between public accounts
LEZ includes a program for managing native tokens. Run `wallet auth-transfer` to see the available commands:
```bash
Commands:
  init  Initialize account under the authenticated-transfer program
  send  Send native tokens from one account to another with variable privacy
  help  Print this message or the help of the given subcommand(s)
```

We already used `init`. Now use `send` to execute a transfer.

### a. Create a recipient account
```bash
wallet account new public

# Output:
Generated new account with account_id Public/Ev1JprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPAWS
```

> [!NOTE]
> The new account is uninitialized. The authenticated-transfer program will claim any uninitialized account used in a transfer, so manual initialization isn’t required.

### b. Send 37 tokens to the new account
```bash
wallet auth-transfer send \
    --from Public/9ypzv6GGr3fwsgxY7EZezg5rz6zj52DPCkmf1vVujEiJ \
    --to Public/Ev1JprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPAWS \
    --amount 37
```

### c. Check both accounts
```bash
# Sender account (use your sender ID)
wallet account get --account-id Public/HrA8TVjBS8UVf9akV7LRhyh6k4c7F6PS7PvqgtPmKAT8

# Output:
Account owned by authenticated-transfer program
{"balance":113}
```

```bash
# Recipient account
wallet account get --account-id Public/Ev1JprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPAWS

# Output:
Account owned by authenticated-transfer program
{"balance":37}
```

## 4. Private account creation

> [!Important]
> Private accounts are structurally identical to public accounts, but their values are stored off-chain. On-chain, only a 32-byte commitment is recorded.
> Transactions include encrypted private values so the owner can recover them, and the decryption keys are never shared.
> Private accounts use two keypairs: nullifier keys for privacy-preserving executions and viewing keys for encrypting and decrypting values.
> The private account ID is derived from the nullifier public key and a numeric identifier: `SHA256(prefix || npk || identifier)`. The same `npk` paired with different identifiers yields different, independent account IDs.
> Private accounts can be initialized by anyone, but once initialized they can only be modified by the owner’s keys.
> Updates include a new commitment and a nullifier for the old state, which prevents linkage between versions.

### a. Create a private account

```bash
wallet account new private

# Output:
Generated new account with account_id Private/HacPU3hakLYzWtSqUPw6TUr8fqoMieVWovsUR6sJf7cL
With npk e6366f79d026c8bd64ae6b3d601f0506832ec682ab54897f205fffe64ec0d951
With vpk 02ddc96d0eb56e00ce14994cfdaec5ae1f76244180a919545983156e3519940a17
```

> [!Tip]
> Save this account ID. You will use it in later commands.

### b. Check the account status

Just like public accounts, new private accounts start out uninitialized:

```bash
wallet account get --account-id Private/HacPU3hakLYzWtSqUPw6TUr8fqoMieVWovsUR6sJf7cL

# Output:
Account is Uninitialized
```

> [!Important]
> Private accounts are never visible to the network. They exist only in your local wallet storage.

## 5. Native token transfer from a public account to a private account

> [!Important]
> Sending tokens to an uninitialized private account causes the authenticated-transfer program to claim it, just like with public accounts. Program logic is the same regardless of account type.

### a. Send 17 tokens to the private account

> [!Note]
> The syntax matches public-to-public transfers, but the recipient is a private ID. This runs locally, generates a proof, and submits it to the sequencer. It may take 30 seconds to 4 minutes.

```bash
wallet auth-transfer send \
    --from Public/Ev1JprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPAWS \
    --to Private/HacPU3hakLYzWtSqUPw6TUr8fqoMieVWovsUR6sJf7cL \
    --amount 17
```

### b. Check both accounts

```bash
# Public sender account
wallet account get --account-id Public/Ev1JprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPAWS

# Output:
Account owned by authenticated-transfer program
{"balance":20}
```

```bash
# Private recipient account
wallet account get --account-id Private/HacPU3hakLYzWtSqUPw6TUr8fqoMieVWovsUR6sJf7cL

# Output:
Account owned by authenticated-transfer program
{"balance":17}
```

> [!Note]
> The last command does not query the network. It works offline because private account data is stored locally. Other users cannot read your private balances.

> [!Caution]
> Private accounts can only be modified by their owner’s keys. The exception is initialization: any user can initialize an uninitialized private account. This enables transfers to a private account owned by someone else, as long as that account is uninitialized.

## 6. Native token transfer from a public account to a private account owned by someone else

> [!Important]
> We’ll simulate transferring to someone else by creating a new private accounts key and treating it as if it belonged to another user. When the recipient is someone else, you only have their `npk` and `vpk` — not an account ID.

### a. Create a new private accounts key to simulate a foreign recipient

```bash
wallet account new private-accounts-key

# Output:
Generated new private accounts key at path /1
With npk 0c95ebc4b3830f53da77bb0b80a276a776cdcf6410932acc718dcdb3f788a00e
With vpk 039fd12a3674a880d3e917804129141e4170d419d1f9e28a3dcf979c1f2369cb72
```

> [!Tip]
> Ignore the account ID here and use the `npk` and `vpk` values to send to a foreign private account.

### b. Send 3 tokens using the recipient’s npk and vpk

```bash
wallet auth-transfer send \
    --from Public/Ev1JprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPAWS \
    --to-npk 0c95ebc4b3830f53da77bb0b80a276a776cdcf6410932acc718dcdb3f788a00e \
    --to-vpk 039fd12a3674a880d3e917804129141e4170d419d1f9e28a3dcf979c1f2369cb72 \
    --amount 3
```

> [!Note]
> `--to-identifier` is omitted here. When omitted, the wallet picks a random identifier, which is usually fine. Use the flag explicitly when a specific identifier is required.

> [!Warning]
> This command creates a privacy-preserving transaction, which may take a few minutes. The updated values are encrypted and included in the transaction.
> Once accepted, the recipient must run `wallet account sync-private` to scan the chain for their encrypted updates and refresh local state.

> [!Note]
> You have seen transfers between two public accounts and from a public sender to a private recipient. Transfers from a private sender, whether to a public account or to another private account, follow the same pattern.

## 7. Sending to a private accounts key from multiple independent senders

> [!Important]
> A private accounts key (`npk` + `vpk`) can be shared with multiple senders. Each sender independently chooses an identifier; the recipient's account ID is derived from `(npk, identifier)`. Two senders using different identifiers produce two separate private accounts under the same key.

### a. Alice creates a private accounts key

```bash
wallet account new private-accounts-key

# Output:
Generated new private accounts key at path /2
With npk a3f7c21b8e905d4f6a1bc783d0e2f94c1d5a6b7e8f9012345678abcdef012345
With vpk 03b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6071819202122232425262728292a2b2c
```

Alice shares the `npk` and `vpk` values with Bob and Charlie out of band.

### b. Bob sends 10 tokens to Alice using identifier 1

```bash
wallet auth-transfer send \
    --from Public/BobXqJprP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPA \
    --to-npk a3f7c21b8e905d4f6a1bc783d0e2f94c1d5a6b7e8f9012345678abcdef012345 \
    --to-vpk 03b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6071819202122232425262728292a2b2c \
    --to-identifier 1 \
    --amount 10
```

### c. Charlie sends 5 tokens to Alice using identifier 2

```bash
wallet auth-transfer send \
    --from Public/CharlieYrP9BmhbFVQyBcbznU8bAXcwrzwRoPTetXdQPB \
    --to-npk a3f7c21b8e905d4f6a1bc783d0e2f94c1d5a6b7e8f9012345678abcdef012345 \
    --to-vpk 03b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6071819202122232425262728292a2b2c \
    --to-identifier 2 \
    --amount 5
```

> [!Note]
> Bob and Charlie each chose a different identifier. They do not need to coordinate — any two distinct values work.

### d. Alice syncs to discover the new accounts

```bash
wallet account sync-private
```

```bash
wallet account list

# Output (private account entries under key /2):
/2 Private/AliceBobAcctXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
/2 Private/AliceCharlieAcctXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Alice now has two separate private accounts, one funded by Bob and one by Charlie, both controlled by the same key at path `/2`.

> [!Tip]
> Alice can check each account balance with `wallet account get --account-id Private/...`. Neither balance is visible on-chain.
