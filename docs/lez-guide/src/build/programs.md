# Programs, deployment and identity

## What a program is

A program is a RISC Zero guest binary with one entry point: the handler. Its **image id** is a hash of the binary. Its **account id** is where it is deployed, and that is the id that appears in every `Actor`.

The two are different on purpose. The same binary can be deployed at several addresses. Each deployment is a separate program: separate actors, separate PDAs.

## Deployment

Programs are deployed through the **program loader**, a built-in pseudo-program at a fixed address (`PROGRAM_LOADER_ACCOUNT_ID`). The loader stores, as its own actor state:

- a **header** at the program's address;
- the bytecode, split over a chain of **segment** accounts.

```rust
pub struct ProgramHeader {
    pub image_id: ProgramId,              // recomputed from the bytecode, never taken on trust
    pub program_first_segment: AccountId,
    pub immutable: bool,                  // once true, the header can never change
}
```

A program has at most 20 segments (`MAX_PROGRAM_SEGMENTS`). The wallet does the splitting:

```text
wallet program-loader deploy --elf path/to/program.bin \
  --header <account> --segments <account>...
```

The accounts must exist first: one header, plus one segment account per 96 KiB of the user ELF (`MAX_SEGMENT_DATA_LEN`). That figure is the client's chunk size and its own comment says so; it is not enforced by the program. What bounds a segment is the per-transaction cap of `max_block_size` less the block overhead. A wrong segment count fails with `SegmentCountMismatch`, which reports the number expected.

Loader messages are allowed only in transactions that carry no proof. A code change must never land in the middle of a transaction whose proof already committed to specific program images.

## Upgrades

A header that is not immutable can be pointed at new bytecode. Two things follow for the author.

- **State layout.** The new code reads actor states written by the old code. Version the layout from the first release.
- **Old messages.** An AsyncMessage sent by the old version may sit in a mailbox for months and be collected after the upgrade. The new handler must still decode and accept every message the old version could have async message.

Marking a program immutable removes both problems and enables undisclosed execution, below.

## Built-in programs

Built-in programs live at ids derived from fixed names:

```rust
AccountId::from_builtin_program_name(b"clock")
```

They are listed in [System programs](system-programs.md). The native token is special: it has a reserved id and no bytecode. The engine and the privacy circuit compute it directly, which is why it needs no inner proof.

## Program identity in a private transaction

When a private handler runs, the proof must say which code it was. There are two ways (`ProgramImageClaim`, `lee/state_machine/core/src/circuit_io.rs`):

| Claim | What is published | Checked by the sequencer |
|---|---|---|
| Disclosed | the program's account id and image id | that this image is deployed at this id |
| Undisclosed | a root of the commitment tree | that the root is a known one |

An undisclosed claim proves that the code is **some** immutable program, without saying which. It works because an immutable program's header is mirrored into the commitment tree, so membership can be proven in zero knowledge. Only immutable programs can run this way.

The code also has a third form, a **shadow program**, identified by its image id alone and never deployed. This book does not use it and has not examined its rules under the actor model.

Choosing between the first two is a privacy decision:

- Disclosed: observers learn that your private transaction used this program.
- Undisclosed: they learn only that it used some immutable program, **and only if that program never crosses the boundary in the transaction.**

That caveat is not a detail. Every boundary entry names an `Actor`, which is `{ account_id, program_account_id }`, and blinding replaces the account id while passing the program account id through in the clear (`lee/state_machine/core/src/execution_state.rs`). So a private-to-public message publishes the sending private actor's program account id, and a public-to-private delivery publishes the receiving one's. Once that id is public the image resolves from it, and the undisclosed claim hides nothing.

Staying off the boundary is necessary but not sufficient. An undisclosed claim proves membership of the set of immutable programs, and every deployment is public, so the set an observer guesses from is only as large as the number of immutable programs on chain.

The bigger limit is that undisclosed is not a property of the program. It is a choice each prover makes per transaction (`ProgramCatalog::with_undisclosed`, `lee/state_machine/src/privacy_preserving_transaction/circuit/mod.rs`), and the default is `Disclosed`. A single transaction by anyone who takes the default publishes the account id and image id for good. Marking a program immutable is what makes undisclosed available to a prover who wants it; it does not keep the program hidden, and an author cannot make that choice on behalf of their users.

## Where a program keeps its state

Three places, and most programs use more than one.

- **On users' accounts.** One actor per user: balances, holdings, seats, badges.
- **On PDAs.** Shared state the program controls: vaults, pools, registries, configuration.
- **On fixed accounts.** For built-ins: the clock accounts, the fee state.

[Where state lives](../patterns/state-placement.md) compares them.
