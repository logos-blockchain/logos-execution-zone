# `lez/chain_state` — Two-Tier Chain State

Design doc for the shared block-apply engine and two-tier chain state that
backs decentralized sequencing. Status: **interface freeze** — the
`apply_block` signature and the `ChainState` tip/state shape below are the
contract the produce-on-turn and follow-blocks tracks build against. Changing
them after the tracks split forces rework in both.

Branch: `erhant/lez-two-tip-chain-state` (off `erhant/indexer-recoverable-invalid-blocks`).

---

## 1. Motivation

Decentralized sequencing requires every honest node — sequencer or indexer — to
converge on the same chain and the same state by running one deterministic
_validate-then-apply_ path over blocks pulled from the channel. That path today
lives only inside the indexer (`lez/indexer/core/src/block_store.rs`), where the
recoverability work built a park-and-skip ingest: `accept_block` validates a
block against the current tip, applies it to a scratch clone of state atomically,
and on any failure records a `StallReason`, freezes the tip, and marks the bad
block _processed_ without applying it. The sequencer has no equivalent — it only
produces blocks and reads peer inscriptions for finalization; it never executes
peer blocks into its own state.

This crate lifts that logic into a shared home and generalizes it into a
**two-tier** state machine so the sequencer can produce on the head while both
sequencer and indexer expose their exact current state.

## 2. Crate placement & layering

```
lee_core  ←  lee (owns V03State)  ←  common (owns Block, BedrockStatus, clock_invocation, recompute_hash)  ←  lez/chain_state  ←  { indexer/core, sequencer/core }
```

- **Not** `lee`: the apply logic needs `Block`/`BedrockStatus`/`clock_invocation`
  from `common`, and `common` depends on `lee` — putting it in `lee` inverts the
  layer.
- `lez/chain_state` sits above `common`, depends on `common` + `lee`, and is
  consumed by both `indexer/core` and `sequencer/core`.

**Persistence boundary.** `chain_state` holds the in-memory state machine and the
pure logic; it performs **no I/O**. Each consumer keeps its own `RocksDBIO` and
drives the `scratch → put_block → commit` ordering, exactly as `accept_block` does
today. This keeps the crate fully unit-testable without a DB.

## 3. The `apply_block` entry point

A single pure function, called identically whether the block was produced by us,
adopted from a peer, or read finalized from the channel:

```rust
/// Validate `block` against `tip`, then apply it to `state`. Pure: no I/O.
/// Mutates `state` only on success; on failure `state` is untouched and the
/// caller parks.
fn apply_block(
    tip: Option<&Tip>,
    block: &Block,
    state: &mut V03State,
) -> Result<(), BlockIngestError>;
```

Validation order (unchanged from the indexer): hash integrity
(`recompute_hash`) → block-id continuity → `prev_block_hash` linkage, with a
`None` tip expecting the genesis block. Application splits off the mandatory
trailing clock tx, executes user txs (genesis = public-only), applies the clock
last.

Shared types moved into the crate: `AcceptOutcome`, `BlockIngestError`,
`StallReason`, and `Tip`.

```rust
struct Tip { block_id: u64, hash: HashType, l1_slot: Slot }

enum AcceptOutcome { Applied, AlreadyApplied, Parked(BlockIngestError) }
```

`Tip` carries `l1_slot` (recorded atomically with the tip) because the anchor /
chain-consistency logic keys on the inscription slot, not just `(id, hash)`.

## 4. The two-tier `ChainState`

```rust
struct ChainState {
    final_state:  V03State,        // driven by finalized channel ops
    final_tip:    Option<Tip>,
    head_state:   V03State,        // final_state + applied head blocks
    head_blocks:  Vec<HeadEntry>,  // ordered, above final_tip
    final_stall:  Option<StallReason>,  // persisted to RocksDB — see §4a
    head_stall:   Option<StallReason>,  // in-memory only — recomputed from the stream on restart
}

struct HeadEntry { this_msg: MsgId, block: Block }
```

The **head** tier is a MsgId-keyed chain (adopted/orphaned reference
`this_msg`/`parent_msg`); the **final** tier is block-id-keyed. `apply_block`
validation stays LEZ-level (`block_id` + `prev_block_hash`) — the two chains run
in parallel and must agree, so we validate via `apply_block` _and_ track `MsgId`
for revert correlation.

Operations:

- `apply_adopted(inscription) -> AcceptOutcome` — dedup by `this_msg` against our
  outbox, else `apply_block` on the head tip; on success push `HeadEntry`. On
  failure, set **`head_stall`** (in-memory `StallReason`) and freeze the head tip
  at the last valid block — do **not** persist.
- `apply_channel_update(orphaned, adopted)` — revert every `orphaned` by
  `this_msg`, re-derive `head_state` (clone `final_state`, replay survivors),
  then apply every `adopted` in order. Atomic per event.
- `finalize_up_to(block_id)` — move `head_blocks` up to `block_id` into
  `final_state` (already validated; a move, not a re-apply).
- `apply_finalized(inscription)` — steady state: if present in head by
  `this_msg`, `finalize_up_to`; cold-start backfill (not in head):
  `apply_block` directly to `final_state`, mirror into head. If a finalized block
  fails to apply, set **`final_stall`** and persist it — this is the **only**
  `StallReason` written to disk (see §4a).
- `rollback_orphan(this_msg)` — drop from that entry forward, re-derive head;
  clears `head_stall` if the re-derived head is clean.
- `status() -> { final_height, head_height, head_stall, final_stall }` — for RPC/UI.

For the **indexer** (finalized-only `next_messages` stream), `head_blocks` stays
empty and `head == final`; it exercises only `apply_finalized`. The **sequencer**
uses both tiers from day one.

### 4a. Two stalls — persisted vs in-memory

Both tiers carry a `StallReason` (`final_stall`, `head_stall`); they are equally
informative. The difference is **persistence**, which follows from durability. L1
finality is about inscription **canonicality**, not LEZ-block **content**
validity, so an authorized sequencer can get a content-invalid block finalized —
which is why both tiers can meet an invalid block in the first place.

- **`head_stall` — in-memory only.** The head is reorg-able and re-derived from
  every `channel_update`. An invalid adopted block is transient: it is either
  orphaned (a competing valid block at the same height wins) or it finalizes. We
  set `head_stall` for observability (RPC/UI can show "head blocked at `N`:
  StateTransition at tx 3") and freeze the head tip at the last valid block, but
  we do **not** write it to disk — on restart the head is rebuilt from the stream,
  so a persisted head stall would be redundant and could go stale. Because the
  next adopted block chains on the bad one, it fails validation too, so the head
  stays frozen until a valid block (competing or post-reorg) is adopted.
- **`final_stall` — persisted.** The final tier is irreversible. If an invalid
  block *finalizes*, the node is durably stuck until a valid successor (built by
  honest sequencers on the last valid parent) finalizes. This must survive
  restart: the startup chain-consistency / anchor check reads it, it is what we
  surface as `Stalled`, and it is the signal the committee acts on to evict a bad
  sequencer.

An invalid block **migrates the problem head→final** when it finalizes: `head_stall`
is set at `N` first; once `N+1(bad)` finalizes, `apply_finalized` fails and records
the persisted `final_stall`. Both tiers end up stuck at `N` consistently, and both
recover when `N+1′` finalizes. The indexer (final tier only) never sets
`head_stall`, so it behaves exactly as it does today.

### 4b. Producer contract — write on turn, build on last valid

The sequencer publishes **only on its own turn** (the SDK queues out-of-turn
publishes). When it is our turn we build the next block on the **current head
tip**, which is by construction the last validly-applied block. So if the head is
frozen (`head_stall` set) on a peer's bad block, we build on that frozen valid
tip — the same parent every honest sequencer chooses — and thereby skip the bad
block rather than extend it. A parked node keeps following peers' valid blocks as
they arrive; the moment it also gets a turn, it produces the next valid block on
its last valid tip. Net: parking never stops us from producing correctly on our
turn.

## 5. Event → tier mapping

`Event::BlocksProcessed { checkpoint, channel_update: { orphaned, adopted }, finalized }`:

| Input                 | Source                                         | Effect                                              |
| --------------------- | ---------------------------------------------- | --------------------------------------------------- |
| adopted inscription   | `channel_update.adopted`                       | validate + apply to **head**                        |
| orphaned inscription  | `channel_update.orphaned`                      | revert from **head**, return txs to mempool         |
| finalized inscription | `finalized[].ops` (`FinalizedOp::Inscription`) | move head→**final**, or apply directly on backfill  |
| own publish           | publish-return                                 | optimistically apply to **head**, record `this_msg` |

**Golden rules:** (1) validation is deterministic, so every honest node makes the
same accept/park decision. (2) An invalid block is _processed but discarded_ —
never applied, never halts the node. (3) Finalized is never reverted. (4) We
rebuild orphaned blocks ourselves; we do not trust the SDK's republish (it keeps
stale LEZ contents — prev-hash, tx selection, and resulting state were all
computed against the old parent).

---

## 6. Scenarios

### Processing one `BlocksProcessed` event

```mermaid
flowchart TD
    EV["Event::BlocksProcessed"] --> ORPH{"orphaned<br/>non-empty?"}
    ORPH -->|yes| REV["For each orphaned by this_msg:<br/>drop from head_blocks,<br/>return its txs to mempool"]
    REV --> RED["Re-derive head_state:<br/>clone final_state, replay survivors"]
    ORPH -->|no| ADO
    RED --> ADO{"adopted<br/>non-empty?"}
    ADO -->|"yes, in order"| DEDUP{"this_msg in<br/>our outbox?"}
    ADO -->|no| FIN
    DEDUP -->|"yes (our own)"| SKIP["skip: already applied optimistically"]
    DEDUP -->|no| VAL["apply_block on head tip"]
    VAL --> OUT{"AcceptOutcome"}
    OUT -->|Applied| APP["append this_msg+block to head,<br/>advance head tip, clear stall"]
    OUT -->|AlreadyApplied| SKIP
    OUT -->|"Parked(err)"| PARK["set head_stall (in-memory),<br/>freeze head tip — do NOT apply.<br/>Not persisted"]
    SKIP --> FIN
    APP --> FIN
    PARK --> FIN
    FIN{"finalized<br/>inscriptions?"}
    FIN -->|"already in head (steady state)"| MOVE["finalize_up_to:<br/>move head→final, trim head_blocks"]
    FIN -->|"not in head (cold-start backfill)"| DIRECT["apply_block directly to final"]
    DIRECT --> DOK{"applied?"}
    DOK -->|yes| MIRROR["mirror into head"]
    DOK -->|"no (invalid finalized)"| FSTALL["record StallReason on FINAL,<br/>freeze final tip"]
    FIN -->|none| CP
    MOVE --> CP
    MIRROR --> CP
    FSTALL --> CP
    CP["persist checkpoint atomically"]
```

### Park / recovery status

```mermaid
stateDiagram-v2
    [*] --> Syncing
    Syncing --> CaughtUp: stream drained, no stall
    CaughtUp --> Syncing: new adopted / finalized arrives
    Syncing --> Parked: invalid block FINALIZED (apply_finalized fails)
    Parked --> Parked: further non-chaining finalized blocks (orphans_since++)
    Parked --> Syncing: valid successor finalizes on frozen final tip → stall cleared
    note right of Parked
        final_stall — persisted, survives restart.
        Head-tier bad blocks do NOT enter this state:
        they set head_stall (in-memory) and self-heal
        via reorg/finalization. Producer (on our turn)
        builds on the last valid tip either way.
    end note
```

### Scenario table

**Normal flow**

| #   | Scenario                                 | Handling                                                      | Expected                            |
| --- | ---------------------------------------- | ------------------------------------------------------------- | ----------------------------------- |
| 1   | Adopted block chains cleanly on head tip | `apply_block` → `Applied`; append `{this_msg, block}` to head | head advances; converges with peers |
| 2   | Our own block comes back in `adopted`    | dedup by `this_msg` against outbox → skip                     | no double-apply                     |
| 3   | Adopted block later finalizes            | `finalize_up_to` moves head→final, trims `head_blocks`        | final advances; no re-apply         |
| 4   | Re-delivery of an already-applied block  | id ≤ tip & stored hash matches → `AlreadyApplied`             | idempotent, no state change         |

**Reorg / orphan**

| #   | Scenario                                                   | Handling                                                                                     | Expected                                        |
| --- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| 5   | Our block orphaned at turn handoff (stale-parent race)     | revert by `this_msg`, return txs to mempool, **rebuild** on new head tip (not SDK republish) | our txs re-queued; next block on correct parent |
| 6   | Batch reorg: some `orphaned` + some `adopted` in one event | revert all orphaned, re-derive head, then apply all adopted in order                         | deterministic convergence                       |
| 7   | Orphan chain (parent transitively off canonical)           | SDK surfaces all affected as `orphaned`; revert each, replay survivors                       | head_state matches new canonical branch         |

**Invalid / bad block** — "stall" below means the **persisted `final_stall`**
(§4a). A bad block seen only in `adopted` sets the in-memory `head_stall` (not
persisted); it becomes a persisted `final_stall` only if it finalizes.

| #   | Scenario                                                            | Handling                                                                                 | Expected                                        |
| --- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------- |
| 8   | Authorized sequencer posts a block with an invalid state transition | head: `apply_block` → `Parked`, set `head_stall` (in-memory), no persist. If it finalizes: persisted `final_stall` | park-and-skip; no apply, no halt                |
| 9   | Broken chain link / hash mismatch / unexpected id in adopted        | `Parked(BrokenChainLink / HashMismatch / UnexpectedBlockId)`; same park                  | frozen tip; peers park identically              |
| 10  | Undeserializable inscription payload                                | park with `Deserialize` (no header); processing advances                                 | recover when a valid block chains on frozen tip |
| 11  | Valid successor after a park (recovery)                             | block chaining on frozen tip → `Applied` → clear stall                                   | head resumes automatically; no divergence       |
| 12  | Further non-chaining blocks while parked                            | keep first `StallReason`, bump `orphans_since`                                           | original cause preserved; still parked          |

**Producing while parked**

| #   | Scenario                                        | Handling                                                                                        | Expected                                                                                   |
| --- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| 13  | It's our turn but head is parked on a bad block | producer builds on the **frozen valid tip** (head tip = last valid), skipping the invalid block | we emit the next valid block on the same parent honest peers use — chain moves on our turn |

**Startup / backfill**

| #   | Scenario                                            | Handling                                                                                           | Expected                              |
| --- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------- |
| 14  | Cold start / reconnect backfill                     | history via `finalized`, empty `channel_update`; apply directly to final + mirror head             | head == final until live deltas start |
| 15  | Local store belongs to a different chain (L1 reset) | anchor-based `chain_consistency` check at startup: wipe+reindex if `allow_chain_reset`, else error | no silent divergence                  |

## 7. Invariants

Should-never-happen conditions — assert/log, don't silently absorb:

- An `orphaned` entry never references a block at or below the **final** tip —
  finalized is irreversible. If seen, it is a bug.
- `head` tip ≥ `final` tip at all times; `head_blocks` holds exactly the blocks
  between them.
- After processing any event, `head_state == final_state` replayed through
  `head_blocks` (the re-derivation is the source of truth).
- A parked node's frozen tip is identical across all honest nodes for the same
  invalid block (deterministic validation).
