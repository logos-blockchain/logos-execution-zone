# Reading the chain

Writing is one command. Reading back is where public and private accounts stop looking alike.

## A public account

```bash
wallet account get --scope all --account-id Public/<id>
```

`--scope` takes three forms:

| `--scope` | Reads |
|---|---|
| `balance` | the native balance only. This is the default |
| `all` | every program's state on the account |
| `<program account id>` | one program's state |

Prefer a single program's id once an account has accumulated state. A full read can exceed the response limit.

Add `--raw` to get the underlying bytes as hex instead of the wallet's decoding:

```bash
wallet account get --raw --scope all --account-id Public/<id>
```

```json
{
  "actor_states": { "<program account id>": "486f6c61206d756e646f21" },
  "nonce": 0
}
```

`actor_states` is keyed by program, because each program owns its own state on the account and cannot touch another's. Decode a value with whatever that program uses; for plain bytes, `echo <hex> | xxd -r -p`.

Without `--raw` the wallet prints each program's state separately and decodes the ones it recognizes.

## A private account

Two commands, in this order, and the order is the whole point:

```bash
wallet account sync-private
wallet account get --scope all --account-id Private/<id>
```

Run the read first and the account says `Account is Uninitialized`, even though it has state. The chain holds a commitment and an encrypted note, not your data, so the wallet has to scan for notes it can decrypt and build a local picture. `sync-private` is that scan.

This is not a cache you can skip. There is no query that returns a private account's contents, for you or anyone else, because the server does not have the keys.

A private account's nonce also looks wrong at first glance: a large number rather than a small counter. It is a hash chain rather than a count, which is what lets two versions of the same account be ordered without being linkable.

## The chain itself

```bash
wallet chain-info current-block-id
wallet chain-info block --id <n>
wallet chain-info transaction --hash <32-byte hex>
```

`current-block-id` is the tip, which is not the same as the last finalized block. If you care whether something can still be undone, that distinction matters, and [Finality](../integrate/finality.md) explains it.

## When something is missing

A transaction you submitted and cannot find is usually one of three things. It has not been included yet, so wait a block. It was refused, in which case nothing happened at all and there is nothing to find; private transactions that fail at settlement are simply not included, and cost nothing. Or it touched a private account and you have not synced.

## Programmatic access

Everything here has an RPC equivalent, and more besides, including event queries and a subscription for finalized blocks. See [Reading state from a client](../integrate/reading-state.md).
