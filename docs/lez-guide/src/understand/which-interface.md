# Which interface you are writing for

LEZ has two program interfaces, and the one you need depends on which version you are building against. Get this wrong and nothing in Part III will compile.

| You are building against | Interface | This guide |
|---|---|---|
| Testnet, today | plan/apply | Parts I, II and IV apply. Part III and Part V describe the other interface |
| The latest release, `v0.3.1` | plan/apply | same |
| `v0.4.0`, when it ships | actors | the whole guide applies |
| `dev`, today | actors | the whole guide applies |

The actor interface merged to `dev` and ships in `v0.4.0`. Until then, every released version and the testnet deployment run plan/apply. `main` is still on the earlier interface, and no tag contains the actor merge.

The deployed programs follow the releases, not `dev`. The token, AMM and ATA programs in `logos-blockchain/lez-programs`, which are live on testnet, are plan/apply programs: their code uses `ChainedCall`, `Claim` and `lee_core::account::Data`.

## What actually differs

A plan/apply program was two entrypoints. `plan` saw the account selectors, whether each was authorized, and the instruction, and emitted effects, which were small proposals each aimed at one shard, plus chained calls to other programs. `apply` then ran once per effect with that one shard's current bytes, and either rewrote it or only checked it.

An actor program is one handler. It receives one message, sees one actor's state, and returns a new state plus the messages it wants sent. There are no effects and no separate apply, because the handler writes its own state directly.

| plan/apply | actors |
|---|---|
| `plan` and `apply` entrypoints | one handler |
| `run_program(plan, apply)` | `actor_entrypoint!(handle_message)` |
| `Effect` aimed at a shard | the handler writes its own state |
| shard | actor state |
| `ProgramShardSelector` | `Actor` |
| `PlanInput` / `ApplyInput` | `ReceiveInput` |
| chained call | `SyncMessage` |
| no counterpart | `AsyncMessage`, and the mailbox |
| `MAX_NUMBER_CHAINED_CALLS` of 10 | no depth cap |
| per-shard `DATA_MAX_LENGTH` of 100 KiB | no cap on actor state size |
| 32-byte `identifier` in private account ids | removed: one key pair, one regular private account |
| deterministic init nullifier `H(account_id)` | keyed by `nsk` |
| view tag published per note | removed |

## Why it changed

The short version is that plan/apply could not express a program paying someone who was offline.

Under plan/apply a program affected another account by proposing an effect, and every effect in a transaction had to be applied within it. A private account can only be advanced by its owner's proof, so a program could not pay a private recipient at all unless that recipient was party to the transaction. The actor model adds the async message and the mailbox: a payment to a stranger's private account is stored on chain and collected later, by its owner, in their own transaction.

The last three rows of the table are worth noticing on their own. The actor model also closed three correlation channels that plan/apply had: the view tag that was key-derived on an init note, the deterministic initialization nullifier, and the identifier that let one key pair hold many distinct private accounts. None of those were the motivation, and all three are real privacy improvements.

## If you are on plan/apply

The full manual for it is preserved at `docs/program-development-book/`, last true at commit `8d8ae6e6b`. It documents the interface that is actually running, and it should stay until `v0.4.0` ships.

Use the table above when reading older material. Designs, issues and review discussions from before the change are still mostly correct in their reasoning even where the mechanism has a different name now.
