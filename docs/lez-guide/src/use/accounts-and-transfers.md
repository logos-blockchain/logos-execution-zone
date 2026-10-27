# Accounts and transfers

Moving native tokens between accounts, at every combination of public and private.

The transcripts below come from a local devnet, so your ids and block heights will differ. Two things are elided, and nothing else is changed. Every send prints a third line, `Transaction data is <the whole transaction, Debug-formatted>`, which runs to about 50,000 characters for a privacy-preserving transfer; it appears below as `Transaction data is …`. Viewing keys are 1184 bytes and are cut to their first 24 characters, also with `…`.

The flag table below is the surface of `lez/wallet/src/cli/programs/native_token_transfer.rs`.

> **Set a password.** On the current `dev` tree, an unencrypted wallet store cannot be read back once it holds a synced private account, because a private account's nonce does not survive the round trip. Every later command then fails with `Failed to parse storage file`, including the one that would set a password. This walkthrough was run with a password set, and so should yours.

## Making accounts

```
$ wallet account new public --label alice
Generated new account with account_id Public/Exqu6DeLJbRd9XGrGxkDKaFjB3RyVG1UqmFoXfP6diuF at path /0
With pk 47235cb72c5d5547aa224ddebe42349075d0c001f1f08f9cf21ff3357354ed51

$ wallet account new private --label bob-private
Generated new account with account_id Private/9zfP6KJnHKS5xeyg4BCksELxyPuk5CkZBUQ8gz6EYCmx at path /0
With npk 2fa1f7f34f518176521db5da6adba67f224dcc43e4daf1172732abe3141b33b2
With vpk 18ebbc68d9b1c22858794bbe…

$ wallet account list
Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
/ Public/3J8K1QHWSq2TbJUYD7XpuvpkeDdcrHPnL9G9kkKEwqkc
/0 Public/Exqu6DeLJbRd9XGrGxkDKaFjB3RyVG1UqmFoXfP6diuF [alice]
/ Private/9oNQfg7f6k1vgnmJjrBUSmMXpcJ4rfnf1yebW32esfck
/0 Private/9zfP6KJnHKS5xeyg4BCksELxyPuk5CkZBUQ8gz6EYCmx [bob-private]
```

The leading token is the derivation path the account came from, and it is blank for an imported key. A label is unique across the wallet and usable anywhere an account id is, including `--to` and `--account-id`.

New accounts are uninitialized until something writes to them. The payer of a transfer must already hold tokens, because a fresh account cannot fund its own first transaction. On a local devnet, start from the genesis-funded key in `lez/sequencer/service/configs/debug/sequencer_config.json`:

```
$ wallet account import public --private-key 7f273098f25b71e6c005a9519f2678da8d1c7f01f6a27778e2d9948abdf901fb
Imported public account Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r

$ wallet account get --scope balance --account-id Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
Balance 9999999245648, nonce 2
```

Against any other sequencer configuration there is no funded account, and the walkthrough stops at the first send.

## Sending

One command, and which flags you use depends on what you know about the recipient.

```bash
wallet auth-transfer send --from <account> --amount <n> <recipient flags>
```

| Recipient | Flag | What it takes |
|---|---|---|
| Any public account, or a private one this wallet owns | `--to` | a base58 account id with its `Public/` or `Private/` prefix, or a label. A `Public/` id needs no ownership; a `Private/` one does, because the wallet has to witness it |
| Someone else's private account | `--to-npk` and `--to-vpk` | the nullifier public key as 32-byte hex, and the ML-KEM-768 viewing key as hex, 1184 bytes |
| Someone else's private account, from a file | `--to-keys` | a path to a keys file holding npk and vpk on separate lines. Replaces the two flags above |
| A public account that has never been used | `--to-pk` | the recipient's public key |

`--from` and `--amount` are always required.

`--to` also accepts a BIP-32 key path, but only one written with a leading `m/`: anything else is read as a label, so copying a `/0` out of `wallet account list` fails with `No account found for label '/0'`. A key path resolves through a connected Keycard and prompts for its PIN, and it always names a public account, never a private one.

Two of the exclusions are enforced by the argument parser and will fail before anything runs: `--to-keys` conflicts with `--to-npk` and `--to-vpk`, and `--to-pk` conflicts with all the others. The remaining rule, that `--to` and the key pair are different patterns, is checked when the recipient is resolved rather than by the parser. Use `--to` for an account this wallet owns, and the keys for anyone else's.

Public to public is one transaction and no proof:

```
$ wallet auth-transfer send --from Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r --to alice --amount 500000
Transaction hash is 1aae5024b5b54641ec60227dd2c6367542411874849933a0c2715a9d3d2abb90
Transaction is included in block 41
Transaction data is …

$ wallet account get --scope balance --account-id alice
Label: alice
Balance 500000, nonce 0
```

Alice's nonce stays 0 because only the accounts that signed advance it, and she only received.

Paying a private account this wallet owns is a privacy-preserving transaction, so it takes noticeably longer, and reading it back needs a sync first:

```
$ wallet auth-transfer send --from Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r --to bob-private --amount 250000
Transaction hash is 6e61e6eec5b3ba37902257183b693458d704b3c575721a493575d02fbb59d189
Transaction is included in block 43
Transaction data is …

$ wallet account sync-private
Latest block is 44
Syncing to block 44. Blocks to sync: 44
Synced to block 44 in 413.516459ms

$ wallet account get --scope balance --account-id bob-private
Label: bob-private
Balance 250000, nonce 13237890985107256710551544753992414516
```

That nonce is not a counter. A private account's nonce is derived by hashing, so it is a large number that changes unpredictably with each update, and it tells you nothing about how many times the account has been used.

## Getting someone's keys

A private account's address is derived from its two public keys, so paying one means holding them. The owner exports them, from their own wallet:

```
$ wallet account show-keys --account-id Private/DaYTiJJrqRu87vf3PBf1YpM5ZjG4xPQEMmqrBjUG4VjR
47b6e0bec3af23da63c8f1c830e00eb0346796cef6bf1b99d3dee8a3c0770f5c
5bf1900a93b359f72d6f58…
```

Two lines, npk then vpk, 64 and 2368 hex characters. Redirect it to a file and send that file to whoever is paying you; it is what `--to-keys` takes. `show-keys` works only for private accounts.

There is no identifier to choose. A private account id is `SHA256(prefix ‖ npk ‖ vpk)`, so one key pair is exactly one regular private account. Material written before `v0.4.0` describes a 32-byte identifier that diversified them; it was removed. See [Which interface you are writing for](../understand/which-interface.md).

## Where the money lands, and why it matters

This is the part most easily got wrong, and it decides which command you run next.

If the recipient is an account this wallet owns, the credit is applied in the transaction, as `bob-private` above shows.

If the recipient is someone else's private account, named by keys rather than owned here, the credit cannot be applied: only its owner can produce the proof that advances it. So it is stored on chain and waits. The sender's side looks the same as any other transfer:

```
$ wallet auth-transfer send --from Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r --to-keys carol.keys --amount 100000
Transaction hash is 00d4cdea846fe2e75e68228c6082e6cef1d04b9a32b6ebe46c214a5a73e04433
Transaction is included in block 45
Transaction data is …
```

The recipient collects it, in the wallet that owns those keys:

```
$ wallet pending list
Message 28: to DaYTiJJrqRu87vf3PBf1YpM5ZjG4xPQEMmqrBjUG4VjR at program 11111111111111111111111111111111, from CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r at program 11111111111111111111111111111111, 17 bytes

$ wallet pending receive --position 28
Transaction hash is e1fb46320509bc116d189d0ef1fa7ad5e237b2910938d239492aef195a4267bf
Transaction is included in block 50
Transaction data is …

$ wallet account sync-private
Latest block is 52
Synced to block 52 in 42.355167ms

$ wallet account get --scope balance --account-id Private/DaYTiJJrqRu87vf3PBf1YpM5ZjG4xPQEMmqrBjUG4VjR
Label: carol
Balance 100000, nonce 285803825814794652966473399278873215916
```

`--position` takes the number `pending list` prints, which is the message's position in the chain-wide mailbox. It is not an index into your own list, so the first message you are shown is almost never at position 0. Passing one that is not yours fails with `No pending message at this position`.

Collecting is itself a privacy-preserving transaction, so it costs the recipient proving time. No amount of `wallet account sync-private` will surface the credit before you collect it, because it is not in the account yet. [Pending messages](pending-messages.md) explains why that asymmetry exists.

## Reading the result

```bash
wallet account get --scope balance --account-id Public/<id>
wallet account sync-private
wallet account get --scope balance --account-id Private/<id>
```

The sync is not optional for a private account, and it must come first. [Reading the chain](reading-the-chain.md) covers the rest.

## What is still missing here

What a failed transfer looks like, and the private-to-private combination, where the sender pays proving time on both sides.
