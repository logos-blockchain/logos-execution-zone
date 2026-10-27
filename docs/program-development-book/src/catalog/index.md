# How to read the catalog

Each entry in this part follows the same shape.

- **Goal.** One paragraph on what the program does for its users.
- **Accounts.** Which accounts are involved, where each one lives (see [Where state lives](../patterns/state-placement.md)), and who authorizes it.
- **Instructions and effects.** The `Instruction` and `Effect` enums, with a note on which effects are guards.
- **A simple version.** Illustrative Rust in the `plan`/`apply` style. It is written to the real API and to compile in shape, but it has not been built, deployed or tested. Where a builtin program already implements the idea, the entry points at the real code instead of repeating it.
- **Interoperability matrix.** For every meaningful combination of public and private placement of the participants, whether the design works, how the transaction is built, and what it reveals. The columns say **Pub** for a public account and **Priv** for a private one.
- **What leaks.** The specific fields an observer learns, following [What a private transaction reveals](../privacy/what-leaks.md).
- **Variations and ideas.** Ways to extend, and designs that were considered and do not work with the current protocol, with the reason.

## Reading the execution diagrams

Most entries include small diagrams of example executions, all drawn the same way:

{{#include ../diagrams/legend.svg}}

- **One column per step** (or, where the subtitle says so, per alternative).
- **Hidden** (blue) is what stays with the participants: who they are, their secrets, amounts in private accounts.
- **On chain** (amber) is what everyone can see for that step.
- **Only unlinkable notes** means the step left nothing on chain but nullifiers and commitments: every wallet-built private transaction shows seven of them, indistinguishable from each other. A deployed program that runs in a private transaction is also named in its claims, unless it is undisclosed or shadow; the diagrams show that as a "program named" chip where it applies.
- The **arrow** is the transaction: dashed for a private one (a proof), solid for a signed public one. A red step was refused and changed nothing.
- A **grey** step with no arrow happens off chain, between the participants. No transaction is sent.

The diagrams are deliberately terse. The text around each one says why it looks the way it does.

The entries are ordered from simplest to most involved. Private donations first, because it is the smallest complete use of the private receive model. Multisig second, because it is the clearest tour of the public/private combinations. Tokens and the AMM are the shipped programs, read as case studies. Streams and voting are the "creative" set the model was not built for and mostly handles. Rate-limiting nullifiers is a toy version of a registry that Logos runs on LEZ. Escrow, auctions and attestations round it out. [Payment channels](channels.md) sit next to streams as the off-chain way to pay over time. Three games follow: [LeZork](lezork.md), [Battleship](battleship.md) and [Deep Space Radio](radio.md), which show hidden state that still has to answer truthfully. The [idea catalog](ideas.md) closes with many shorter designs and a list of things that do not fit.

A caution that applies to every entry: privacy claims are made against the protocol as it is, including the interim choices (no private fees, seven-account padding, one-byte view tags). Re-check them against [What you cannot do privately](../privacy/limits.md) when those change.
