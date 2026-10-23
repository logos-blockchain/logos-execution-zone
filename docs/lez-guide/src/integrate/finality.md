# Finality

A LEZ transaction passes through three states, and a client that treats the first as the last will eventually show a user something that gets taken away.

It is **included** when the sequencer puts it in a zone block. It is **settled** when the sequencer has applied its deferred public effects, which for a private transaction is a distinct event from inclusion. It is **final** when the Logos L1 channel carrying that zone block has itself become immutable.

Only the third is irreversible, and only the third is what `getLastFinalizedBlockId` reports.

## Where finality comes from

LEZ does not decide its own finality. It is a channel on the Logos blockchain, and it inherits that chain's notion of immutability.

The L1 runs Cryptarchia, a proof-of-stake consensus whose finality is probabilistic rather than absolute. Its `Config` carries a `security_param`, documented in the code as "the `k` parameter in the Common Prefix property. Blocks deeper than k are generally considered stable and forks deeper than that trigger the additional fork selection rule, which is however only expected to be used during bootstrapping" (`logos-blockchain/logos-blockchain: consensus/cryptarchia-engine/src/config.rs`).

The latest immutable block is computed from exactly that parameter. In the online state it is the `k`-deep ancestor of the local chain tip, `branches.nth_ancestor(&local_chain, security_param)` (`logos-blockchain/logos-blockchain: consensus/cryptarchia-engine/src/lib.rs`).

So `k` is the whole answer, and it is a deployment parameter rather than a constant:

| Deployment | `security_param` |
|---|---|
| Node default | 30 |
| Testnet deployment template | 120 |

Sources: `logos-blockchain/logos-blockchain: nodes/node/standalone-deployment-config.yaml` and `deployment/ceremony/genesis/testnet/deployment-template.yaml`.

There is no point at which an L1 block becomes mathematically irreversible. Depth buys confidence, and `k` is the depth at which the protocol stops entertaining alternatives.

## How a zone block becomes final

A zone is a channel. The sequencer writes its blocks into that channel as inscriptions, each referencing the previous message by `MsgId`, so the channel is itself a chain (`logos-blockchain/logos-blockchain: core/src/mantle/ops/channel/{mod.rs,inscribe.rs}`). Deposits and withdrawals are operations on the same channel.

The sequencer then watches the channel. The comment in the code states the rule exactly: the channel serving a block "is what makes it irreversible" (`lez/sequencer/core/src/lib.rs`). When the L1 finalizes channel messages, the zone blocks they carried move into a final tier. The sequencer collects the newly final blocks together with any re-delivered ones into a set it calls `irreversible`, and takes the highest block id among them:

```rust
// Every block at or below the highest finalized one is irreversible, so
// stored blocks there can be marked finalized.
let last_finalized = irreversible.iter().map(|block| block.header.block_id).max();
```

Because everything at or below that height is irreversible, finality is a single watermark rather than a per-block flag.

## What a client should do

Read the watermark, or subscribe to it:

```
getLastFinalizedBlockId      -> Option<BlockId>
subscribeToFinalizedBlocks   -> stream of finalized blocks
```

The honest pattern for anything with value attached: show the transaction as soon as it is included, label it as pending, and only treat it as done once its block id is at or below the watermark. The wait is `k` L1 blocks plus however long the channel takes to carry the zone block, which on a 120-deep testnet is substantial.

For a transaction with no value attached, inclusion is usually enough. The distinction a client should never blur is between the two.

## What a program author should assume

Nothing in a handler can observe finality. A handler sees one message and one actor's state, and it runs either on the sequencer or in a proof; in neither case does it know how deep its block is. Time is available only by asserting against the clock, which is itself zone state ([System programs](../build/system-programs.md)).

So finality is a client concern, not a program concern. The one place it reaches into program semantics is the bridge: a deposit observed in a finalized block is permanently minted, because its receipt is then in the irreversible tier, and the sequencer drops the pending record that was tracking it. Until then the mint is reversible along with its block.

## Settlement is not finality

This distinction is worth stating plainly, because this guide covers settlement at length and barely mentioned finality before this chapter.

A private transaction's effects on public accounts are applied by the sequencer at settlement, against live state, after the proof is verified ([Transactions](../build/transactions.md)). That is why a prepared private transaction can be built now and still settle correctly later. Settlement decides whether a transaction takes effect at all. Finality decides whether that effect can still be undone.

A reader who has absorbed the settlement chapters may believe they understand finality. They are different events, with different causes, and only one of them involves the L1.
