# Introduction

The Logos Execution Zone (LEZ) is a programmable chain with two kinds of accounts, public and private, that programs treat identically. A program is a RISC Zero guest binary. It never learns whether the accounts it is given are public or private. The same bytecode runs on the sequencer for a public transaction and inside the user's prover for a private one. Privacy is a property of the transaction, not of the program.

This book is the developer manual for that programming model. It is written against the state of the repository after the "incremental updates" change (pull request 912), which replaced the older read-then-write program interface with the two-entrypoint `plan` / `apply` model described in [Plan and apply](foundations/plan-apply.md). Everything here assumes that model.

> **A newer model.** Pull request 935 replaces plan/apply with transactional actors, and ships in `v0.4.0`. Its manual is `docs/lez-guide/`, which also covers using and integrating with the zone. This book remains the manual for plan/apply, which is what the latest release and the live testnet run. Releases before `v0.3.0` ran an older whole-account interface that neither book documents. A box marked **With actors** in this book says what changes for that design under the new model.

## What this book is

Three things at once.

1. **A manual.** Part I explains every primitive a program author touches: accounts and shards, the plan/apply contract, authorization and program-derived accounts, public and private transactions, keys and notes, program identity, the system programs, and the toolchain.
2. **A map of the privacy model's edges.** Part II says exactly what a private transaction publishes and lists the things that cannot be done privately today. Several of those limits are structural and shape every design in the catalog, so read that part before designing anything.
3. **A catalog of designs.** Parts III and IV turn the primitives into a pattern language and then into concrete programs: private donations, multisig in every public/private combination, tokens, an AMM, payment streams and channels, voting, rate-limiting nullifiers, escrow and auctions, tickets and registries, three games with hidden state, and a long list of further ideas including the ones that do not work and why.

## How to read it

If you have never written an LEZ program, read Part I in order, then Part II, then skim Part III and jump to whichever catalog entry is closest to what you want to build.

If you already know the model and want ideas, start at [How to read the catalog](catalog/index.md). Each entry states the goal, the accounts involved, the instruction and effect types, a simple version of the program, an interoperability matrix across public and private account placements, what the design leaks, and variations.

If you are checking a fact, the reference chapters at the end list the guest API, the account-id derivations, and the protocol constants with their source locations.

## Conventions

- "LEE" is the Logos Execution Environment: the state machine, the program interface and the privacy circuit. "LEZ" is the zone built on it: the sequencer, the wallet, the builtin programs. Program authors mostly deal with LEE types from the `lee_core` crate.
- Code in Part I and Part V is taken from, or matches, the repository. Code in Part IV is illustrative. It follows the real API and is written to compile in shape, but it has not been built or tested. Treat it as a design sketch, not a library.
- "Shard" means the slice of an account's data owned by one program. A program can write only its own shards. This rule is the backbone of the whole model and is stated properly in [Accounts and shards](foundations/accounts.md).
- Amounts are `u128` unless a program says otherwise. Timestamps are Unix milliseconds. Block ids start at 1.
- File paths are relative to the repository root.

## The one-paragraph model

An account is a nonce plus a map from program account ids to byte strings (shards). A transaction names a program, a list of `(account, shard)` selectors and instruction bytes. The program's `plan` entrypoint sees only the selectors, whether each account is authorized, and the instruction; it emits effects (small proposals aimed at one shard each) and chained calls to other programs. Its `apply` entrypoint is then run once per effect with that one shard's current bytes and either rewrites the shard, if the shard belongs to the program, or only checks it. A public transaction runs all of this on the sequencer. A private transaction runs all of it on the user's machine inside a proof, except that effects aimed at public accounts are carried in the clear and applied by the sequencer at settlement. That last sentence is where every privacy limit in this book comes from.
