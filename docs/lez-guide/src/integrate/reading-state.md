# Reading state from a client

The sequencer accepts transactions. The indexer answers questions about what happened. A client talks to both, and almost everything an application needs to display comes from the indexer's JSON-RPC surface.

Source: `lez/indexer/service/rpc/src/lib.rs` for the interface, `lez/indexer/service/protocol/src/lib.rs` for the types.

## The surface

Fifteen methods and two subscriptions.

| Method | Returns |
|---|---|
| `getAccount(account_id)` | the account's full state, or null |
| `getAccountAtBlock(account_id, block_id)` | the same, as of a height |
| `getAccountSummary(account_id)` | a cheaper read for list views |
| `getAccountView(account_id)` | a projected view rather than raw actor states |
| `getAccountViewAtBlock(account_id, block_id)` | the same, as of a height |
| `getBlockById(block_id)` | a block |
| `getBlockByHash(hash)` | a block |
| `getBlocks(range)` | a range of blocks |
| `getTransaction(hash)` | a transaction |
| `getTransactionsByAccount(account_id)` | an account's transaction history |
| `getEvents(filter)` | program events; see [Events](events.md) |
| `getLastFinalizedBlockId()` | the finality watermark; see [Finality](finality.md) |
| `getStatus()` | node status |
| `getSchema()` | the indexer's own schema, which is the authoritative shape reference |
| `checkHealth()` | liveness |

| Subscription | Streams |
|---|---|
| `subscribeToFinalizedBlocks` | blocks as they become irreversible |
| `subscribeToEvents(filter)` | `EventRecord` as events are indexed |

`getSchema` is worth calling once during development rather than transcribing shapes from this page: it is generated from the same types the server uses, so it cannot drift.

## The shape an account comes back in

An account is a nonce and a map from program account id to that program's actor state. The native balance is one of those entries, under the native token program, rather than a field of its own:

```json
{
  "nonce": 0,
  "data": { "actor_states": { "<program account id>": "<bytes>" } }
}
```

`actor_states` is keyed by program, so a client that cares about one program reads one entry and ignores the rest. The bytes are whatever that program writes, and decoding them is the client's job: the indexer does not know a program's state layout. This is the same structure the wallet prints with `wallet account get --raw`.

Prefer `getAccountSummary` or `getAccountView` for list views. A full read of an account that has accumulated large actor states can exceed the response limit.

## The two things the indexer cannot do

It cannot read private accounts. Their contents are not on chain; the chain holds a commitment and an encrypted note. No RPC method will ever return the state of a private account, because the server does not have the keys. The only path is a client that holds them, which means the wallet library ([Building on the wallet library](wallet-sdk.md)) and its `sync-private` scan.

It cannot tell you about a transaction that was refused. A private transaction that fails at settlement is simply not included, so there is nothing to query. A client that submits one and then polls for it must treat "not found" as a possible terminal state rather than as "not yet", and distinguish them by block height.

## It lags the sequencer

The indexer ingests blocks the sequencer has produced. A transaction can be accepted and not yet queryable. For submission and immediate confirmation the wallet library's poller is the better tool: `poll_tx(tx_hash)` returns the transaction and the block it landed in, and `poll_block_range` walks a range (`lez/wallet/src/poller.rs`).

The division that works: submit and confirm through the wallet library, display and search through the indexer.

## The explorer

`lez/explorer_service` is a Leptos front end over the same RPC surface, run with `cargo leptos serve --release`. It is useful as a worked example of the read path, and it calls `get_last_finalized_block_id` among others. Whether it is a supported integration surface or an internal tool has not been decided.
