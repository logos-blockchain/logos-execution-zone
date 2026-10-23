# Programs and deployment

A program is a RISC Zero guest binary (an ELF for the `riscv32im-risc0-zkvm-elf` target) whose `main` hands control to `run_program`. The chain identifies bytecode by its RISC Zero **image id** (`ProgramId = [u32; 8]`), and addresses a deployed program by the **account id** of its header. These are different things, and the difference matters.

## Image id versus account id

- The **image id** is a hash of the bytecode. It is what the privacy circuit verifies receipts against and what a `ProgramImageClaim` commits to. Two deployments of the same bytecode share an image id.
- The **program account id** is the address a transaction dispatches to and the key under which the program's shards live. It is the account that holds the program's header. The same bytecode deployed twice at two headers is two distinct programs: separate shards, separate PDAs, separate `self_account_id`.

Builtin programs shipped in genesis live at a **stable name address**: `AccountId::from_builtin_program_name(b"clock")` is `SHA256("/LEE-BuiltinProgram/v1/AccountId" ‖ "clock")`, and every builtin's core crate exports the helper (`clock_core::clock_account_id()`, `fee_core`, `sequencer_stake_core` and so on, re-exported from the `programs` crate). The address does not change when the bytecode is upgraded, which is the point: a builtin's PDAs and shard keys survive a new image id. `AccountId::from_builtin_program(image_id)`, the image id's bytes reinterpreted, still exists but only as a helper for seeding test programs. A user-deployed program lives wherever its deployer put the header.

## Deployment through the program loader

Deployment is done by the **program loader**, a native pseudo-program at `PROGRAM_LOADER_ACCOUNT_ID` (`[0xFE; 32]`) that runs as Rust on the sequencer rather than as a guest. Its shards hold two record types (`lez/programs/program_loader/core/src/lib.rs`):

```rust
pub struct ProgramSegment {
    pub bytecode: Vec<u8>,                 // a chunk of the user ELF
    pub next_segment: Option<AccountId>,   // toward the head of the chain
}

pub struct ProgramHeader {
    pub image_id: ProgramId,               // recomputed from the chain, never trusted
    pub program_first_segment: AccountId,
    pub immutable: bool,
}
```

Three instructions:

1. `WriteSegment { bytecode, next_segment }` writes one chunk into the empty loader shard of the target account. It is permissionless: nobody signs for the segment account. Segments are linked tail to head, so the last chunk is written first.
2. `CreateHeader { first_segment, immutable }` writes a header into the empty loader shard of an **authorized** account, walking the supplied segment accounts in order and recomputing the image id from the concatenated bytecode. The header target must sign, so a header cannot be squatted at an address someone else will later resolve to.
3. `UpdateHeader { first_segment, immutable }` repoints a mutable header at a new chain. Once `immutable` is set it can never be updated again.

Limits: at most `MAX_PROGRAM_SEGMENTS` = 20 segments, each under 100 KiB, with `MAX_SEGMENT_DATA_LEN` = 96 KiB recommended. Segments hold only the user ELF; the protocol re-attaches its fixed kernel before computing the image id.

The wallet wraps all of this: `wallet program-loader deploy --elf path/to/program.bin --header <account> --segments <account>...` submits the transactions over accounts you created first (`wallet account new public --label ...`, one segment account per 96 KiB of user ELF), and the `ProgramLoader` facade (`lez/wallet/src/program_facades/program_loader.rs`) exposes the same steps to Rust. The examples use `program_deployment::deploy_program`, which returns the header's account id.

Deployment is an ordinary public transaction and is charged like one. It cannot be done privately: the loader is public-only protocol code and the circuit refuses to dispatch to it.

## Upgradeability and immutability

A mutable header lets its owner swap the bytecode under the same account id, which keeps every PDA and every shard key stable across upgrades. Users who call the program have no protection against that beyond trusting the owner. An immutable header is a promise: the account id will always resolve to this image id.

Immutability buys one more thing. When a header becomes immutable, the loader emits a private **mirror commitment** of the header into the commitment set. That commitment is what lets a private transaction later run the program **without disclosing which program it ran**, by proving membership of the mirror instead of naming the account. See [Program identity](program-identity.md).

## Builtin programs

Genesis seeds these programs (`lez/testnet_initial_state/src/lib.rs`), each with an immutable header. The token, associated-token-account and AMM programs used to be here and now live in `logos-blockchain/lez-programs`, deployed rather than genesis-seeded:

| Program | Role |
|---|---|
| `clock` | block id and timestamp, written by the sequencer at the end of every block |
| `fee` | the dual fee market, distribution and refunds |
| `bridge` | L1 deposits (withdrawals are disabled) |
| `sequencer_stake` | committee membership, unstaking, slashing |
| `cross_zone_outbox`, `cross_zone_inbox` | messaging between zones |
| `bridge_lock`, `wrapped_token` | a cross-zone token bridge built on the outbox and inbox |
| `ping_sender`, `ping_receiver` | a minimal cross-zone example |

Two more are native, not guests: the **native token program** at `[0; 32]` and the **program loader** at `[0xFE; 32]`. Both are recomputed from protocol code wherever they run, so they have no image id to claim and cannot be redeployed.

## Anatomy of a program crate

The builtins follow a layout worth copying (see `logos-blockchain/lez-programs: programs/token/`):

- `core/` holds the `Instruction` enum, the on-chain data types with their `ShardData` conversions, and the PDA derivations. It compiles for both the guest and the host, so wallets and tests can build instructions and decode shards.
- `src/lib.rs` holds `plan`, `apply` and the `Effect` enum. It is also host-compilable, which is what makes unit-testing `plan` and `apply` as plain Rust functions possible.
- `src/main.rs` is the guest entrypoint: `fn main() { run_program(plan, apply) }`.

The `Effect` type is private to the program in the sense that nobody else needs to decode it, but its bytes are visible on chain when the effect targets a public account. Keep that in mind when choosing field names and contents; see [What a private transaction reveals](../privacy/what-leaks.md).

## Where a program's own state lives

A program has no state of its own. When it needs global data (a pool, a config, a registry) it puts that data in its shard on a **program-derived account** whose address it can recompute from a fixed seed. The `fee` program keeps its market state at `for_public_pda(fee, "…/FeeSeed/State/…")`; the `amm` keeps each pool at a PDA seeded by the token pair. Chapter [Authorization and PDAs](authorization.md) covers how a program authorizes its own PDAs.
