# What LEZ is

The Logos Execution Zone is a programmable chain where an account can be public or private, and a program cannot tell the difference.

That is the whole claim. Everything else in this guide is a consequence of it.

## The unusual part

On most chains, privacy is a feature of a particular application: a mixer, a shielded pool, a dedicated private token. The application is built for it, and nothing else on the chain can use it.

On LEZ, privacy is a property of the account and the transaction, not of the program. A program is a RISC Zero guest binary that receives a message, sees one account's state, and returns a new state. The same compiled binary runs on the sequencer when the account is public, and inside the owner's own prover when the account is private. The program is not compiled differently, configured differently, or even aware of which case it is in.

The practical consequence: you write one program and it serves both. A token that works for public balances works for private ones. A multisig whose members are public works with members who are hidden. The catalog in Part III is mostly an exploration of that one property, including the places it runs out.

## What it costs

Private execution happens on your machine. Proving a transaction takes from tens of seconds to a few minutes, depending on the machine and how many handlers run. You pay that in latency, not in fees: private transactions are fee-exempt under the current interim policy.

Private state is also yours to find. The chain stores a commitment and an encrypted note rather than your data, so reading your own account back means scanning the chain for notes you can decrypt. The wallet does this with `wallet account sync-private`, and until it runs, a private account reads as uninitialized.

Some things cannot be done privately at all, and the limits are structural rather than temporary. Nobody can make a private actor act, because only its owner can produce the proof. A program cannot read a private account it does not own. A public program cannot react to private state unless the private side chooses to tell it. [What you cannot do privately](../privacy/limits.md) is the full list, and it is worth reading before designing anything.

## Where it sits

LEZ is a zone on the Logos blockchain. In the L1's own words, Logos is "a privacy-preserving, censorship-resistant blockchain for decentralized network states", combining zero-knowledge proofs, a mix network, and a modular service architecture.

A zone is a channel on that chain. The LEZ sequencer produces zone blocks and inscribes them into its channel, and the zone inherits the L1's finality: a zone block is irreversible once the channel message carrying it is. Deposits and withdrawals cross through the same channel. [Finality](../integrate/finality.md) has the mechanism.

Two names appear throughout and are worth separating now. LEE, the Logos Execution Environment, is the state machine, the program interface and the privacy circuit: the part that decides what a program is and what a proof must show. LEZ is the zone built on it: the sequencer, the wallet, the builtin programs. Program authors work almost entirely with LEE types, from the `lee_core` crate.

Proving is RISC Zero. A program is a RISC-V binary for the zkVM, identified by an image id that is a hash of its bytecode.

## What this guide will not tell you

It is not a specification. Where this guide and the code disagree, the code is right, and Part V names the file for every claim so you can check.

It does not cover running validators, staking or the economics of the L1.

## Where to go

If you want to hold and move tokens, or try the chain without writing code, go to [Setting up the wallet](../use/wallet-setup.md).

If you want to write a program, [the quickstart](../build/quickstart.md) has one running in about half an hour, and Part III explains it afterwards.

If you are building a client, a service or a UI against an existing zone, go to [Reading state from a client](../integrate/reading-state.md).

If you want the model before anything else, [The model in one page](the-model-in-one-page.md) is the next page and is exactly what its title says.
