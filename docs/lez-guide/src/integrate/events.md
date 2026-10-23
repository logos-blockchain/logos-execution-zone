# Events

An event is how a program tells the outside world that something happened, without putting it in state.

## Emitting

```rust
pub struct ProgramEvent {
    /// Selector bytes allowing to distinguish event type. By convention, the
    /// first 8 bytes of `sha256("<program>::<EventName>")`.
    pub selector: [u8; 8],
    /// The arbitrary event-data emitted in the program output.
    pub data: Vec<u8>,
}
```

A handler attaches one with `Response::event(..)`. The selector convention matters: it is what lets a consumer filter without decoding, and following it means an indexer can distinguish your events from another program's with the same name.

Source: `lee/state_machine/core/src/program/mod.rs`.

## Consuming

The indexer records each event with the context a consumer needs to make sense of it:

```rust
pub struct EventRecord {
    pub block_id: BlockId,
    pub tx_index: u32,
    pub tx_hash: HashType,
    pub program_account_id: AccountId,
    pub selector: Selector,
    pub data: Vec<u8>,   // base64 over the wire
}
```

Query them with `getEvents`, or stream them with `subscribeToEvents`. Both take the same filter, and every field is optional:

```rust
pub struct EventSubscriptionFilter {
    pub tx_hash: Option<HashType>,
    pub program_account_id: Option<AccountId>,
    pub selector: Option<Selector>,
}
```

Filtering on `program_account_id` plus `selector` is the normal case: one program's one event type. Ranged queries can fail with `FromPastTip`, `ToPastTip` or `Inverted` if the range does not make sense against the current tip.

Source: `lez/indexer/service/protocol/src/lib.rs`.

## The rule that shapes designs

Events emitted by a private handler are dropped. Not encrypted, not deferred: discarded. A private actor's handler runs inside a proof, and its events do not leave it.

So if an indexer or a UI has to learn that something happened, the announcement must come from a public actor. The usual shape is that the private actor sends a message to a public one, which emits the event as part of its own handling. The private side proves the fact; the public side publishes it.

This is the same constraint stated from the design side in [What you cannot do privately](../privacy/limits.md), and it is the most common reason a design that works in testing shows nothing in a UI.

## What events are not

They are not state. Nothing reads them back on chain, no handler can see another actor's events, and a program cannot condition on one. If a fact needs to be enforced, it belongs in an actor's state where a handler can assert on it. Events are for observers.
