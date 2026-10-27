# How to read the catalog

Each entry follows the same shape.

- **Goal.** What the program does for its users.
- **Actors.** Which actors exist, where each lives (see [Where state lives](../patterns/state-placement.md)), and who authorizes it.
- **Messages.** The message types, with who may send each.
- **Handler.** Illustrative Rust. It follows the real API and has not been built or tested. Helper names such as `decode` and `Ship::from_bytes` stand for ordinary serialization code.
- **What to notice.** The points the example exists to make.
- **Public and private.** What changes, and what an observer sees, for each mix of participants.
- **Going further.** What a real version would add, and what does not work.

Patterns are cited by number, as in "(pattern 7)". They are defined in [The pattern language](../patterns/index.md).

## Reading the diagrams

Most entries include small diagrams of example executions:

{{#include ../diagrams/legend.svg}}

- **One column per step.**
- **Hidden** (blue) is what stays with the participants.
- **On chain** (amber) is what everyone can see for that step.
- **Only unlinkable notes** means the step left nothing readable on chain: nullifiers, commitments and encrypted notes.
- The **arrow** is the transaction: dashed for a private one (a proof), solid for a signed public one.
- A **grey** step with no arrow happens off chain, between the participants. No transaction is sent.

The diagrams are terse on purpose. The text around each one explains it.

## Small on purpose

Every entry is the smallest program that shows its idea. A real token has freezing, metadata and allowances; the one here has three messages. Each entry ends with "Going further" for what a real version would add.

Each entry opens with a **Shows** line naming the patterns it demonstrates.

| Entry | The one idea |
|---|---|
| [Private donations](donations.md) | paying someone who is offline and unknown |
| [Payment requests](requests.md) | accepting a message by collecting it |
| [A minimal token](tokens.md) | each actor changes only itself |
| [Multisig](multisig.md) | one program in every public/private combination |
| [Payment streams](streams.md) | a public actor that anyone can move forward |
| [Payment channels](channels.md) | many off-chain payments, two transactions |
| [Private voting](voting.md) | a public tally that trusts hidden voters |
| [Credentials](credentials.md) | proving a fact about yourself under a pseudonym |
| [Rate-limiting nullifiers](rln.md) | a public registry that members can join anonymously |
| [Escrow and sealed bids](escrow-auctions.md) | a public actor between two private parties |
| [Deep Space Radio](radio.md) | all of it, as a game |
| [Battleship](hidden-games.md) | a player who cannot lie about what they hide |
| [Idea catalog](ideas.md) | many shorter designs, and what does not fit |

## A caution

Privacy claims here are made against the protocol as it is, including interim choices: no fees on private transactions, padding to seven private actions, one collected message per transaction. Re-check them against [What you cannot do privately](../privacy/limits.md) when those change.

Nothing in this part has been run. The designs come from reading the engine and the shipped programs.
