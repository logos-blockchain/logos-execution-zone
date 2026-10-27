# The LEZ guide

The Logos Execution Zone is a programmable chain with two kinds of account, public and private, that programs treat identically. A program is a RISC Zero guest binary. It never learns whether the accounts it was given are public or private: the same bytecode runs on the sequencer for a public account and inside the owner's prover for a private one. Privacy is a property of the transaction, not of the program.

> **Which version this describes.** This guide documents the actor program interface, which ships in `v0.4.0`. The latest release, `v0.3.1`, and the live testnet run the earlier plan/apply interface, and two legacy deployments run an older one still. Parts I, II and IV hold either way; Part III and Part V describe actors. Read [Which interface you are writing for](understand/which-interface.md) before anything else: it is two tables, and it tells you whether the rest of this guide is about the chain you are building on.

This guide is organised by how much you need to know, not by subsystem. Each part is self-contained, and you can stop where your need ends.

| Part | For | What it gives you |
|---|---|---|
| [I. Understand LEZ](understand/what-lez-is.md) | everyone | what this is and whether it fits your problem, in about fifteen pages |
| [II. Use LEZ](use/wallet-setup.md) | end users | the wallet: accounts, transfers, reading state, collecting messages |
| [III. Build on LEZ](build/quickstart.md) | program authors | from an empty shell to a deployed program, then the full programming model and a catalog of designs |
| [IV. Integrate with LEZ](integrate/reading-state.md) | client and service developers | the RPC surface, the wallet library, events, finality, running a node |
| [V. Reference and internals](reference/api.md) | anyone checking a fact | the guest API, every derivation and constant, and how the engine and circuit actually work |

If you have never seen LEZ, read Part I in order. If you are here to write a program, [the quickstart](build/quickstart.md) gets something running in about half an hour and Part III explains it afterwards. If you are checking a fact, Part V has the tables.

## Read this before designing anything

Part III's [privacy chapters](privacy/what-leaks.md) say exactly what a private transaction publishes and what cannot be done privately at all. Several of those limits are structural and shape every design in the catalog. Designs that ignore them fail in ways testing does not reveal, because the failure is a leak rather than a crash.

## Conventions

LEE is the Logos Execution Environment: the state machine, the program interface and the privacy circuit. LEZ is the zone built on it: the sequencer, the wallet, the builtin programs. Program authors mostly use types from the `lee_core` crate.

An actor is a pair: an account and a program. "Alice's token actor" means the token program's state on Alice's account.

Code in Parts I, II, III's model chapters and V is taken from the repository or matches it. Code in the catalog is illustrative: it follows the real API but has not been built or tested. Treat it as a design sketch.

Repository paths are relative to the root of `logos-blockchain/logos-execution-zone`. Code in another repository is written as `<org>/<repo>: <path>`.

Amounts are `u128` unless a program says otherwise. Timestamps are Unix milliseconds. Block ids start at 1.

## Where this guide came from

It unifies two earlier books, both by Sergio Chouhy. One documented the plan/apply interface and is kept at `docs/program-development-book/`, because plan/apply is what the latest release and the live testnet run. The other documented the actor interface against pull request 935 before it merged; its content forms Part III here, with the names it predicted brought in line with the code that shipped, and it has been removed so the same material does not live in two places.
