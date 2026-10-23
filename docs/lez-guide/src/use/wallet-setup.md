# Setting up the wallet

The wallet is the command-line client for LEZ. It holds your keys, builds and signs transactions, proves private ones, and reads state back. Everything in this part of the guide uses it.

Install it from the repository root:

```bash
cargo install --path lez/wallet --force
```

Check it can reach a node:

```bash
wallet check-health
```

On first run it asks for a password twice. Set one: an empty password leaves the store unencrypted, and on the current `dev` tree such a store cannot be read back once it holds a synced private account. A non-empty password is required by every later command, or read from `LEE_WALLET_PASSWORD`.

## The commands

| Command | What it does |
|---|---|
| `wallet account` | create, list, read and sync accounts |
| `wallet auth-transfer` | send native tokens, at any public/private combination |
| `wallet chain-info` | `current-block-id`, `block`, `transaction` |
| `wallet pending` | list and receive messages waiting in a mailbox |
| `wallet program-loader` | deploy and update programs |
| `wallet bridge` | withdraw to L1 |
| `wallet group` | group keys: create, new sealing key, invite, join |
| `wallet keycard` | use a Keycard for signing instead of stored keys |
| `wallet config` | `get` and `set` configuration |
| `wallet change-network` | point the wallet at a different node |
| `wallet set-password` | set, change or remove the storage password |
| `wallet restore-keys` | restore keys from a mnemonic at a given depth |
| `wallet check-health` | confirm the wallet is connected to a node |

`wallet help`, and `--help` on any subcommand, prints the authoritative arguments. Shell completions are in the repository's `completions/` directory.

## Where to go next

[Accounts and transfers](accounts-and-transfers.md) creates accounts and moves tokens between them in every public and private combination. [Reading the chain](reading-the-chain.md) covers getting state back out. [Pending messages](pending-messages.md) covers collecting a message someone sent you while you were offline.

If you are here to write programs rather than use them, skip to the [Quickstart](../build/quickstart.md).
