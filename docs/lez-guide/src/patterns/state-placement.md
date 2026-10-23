# Where state lives

Every piece of state a program keeps is an actor on some account. The kind of account decides who can read it, who can change it, and who has to be online for it to change.

| Placement | Who reads | Who can run the handler | Who authorizes | Reached by |
|---|---|---|---|---|
| Public, key-owned | everyone | the sequencer, in any transaction that declares it | the owner's signature | SyncMessage or AsyncMessage, from anyone |
| Public PDA | everyone | the sequencer | the program, by seed | SyncMessage or AsyncMessage, from anyone |
| Private, regular | the owner | the owner, in their own proof | the owner's spending key | SyncMessage from the owner's own transaction; AsyncMessage from anyone |
| Private PDA | the key holder | the key holder | the program, by seed | same as private |
| Group-owned private PDA | every group member | any group member | the program, by seed | same as private |
| The mailbox | clear: everyone; sealed: the recipient | nobody; messages wait | not applicable | AsyncMessage |

## Choosing

Ask four questions about each piece of state.

**Must anyone be able to move it forward?** Then it is public. Pools, tallies, auctions, referees and anything with a deadline belong on a public PDA.

**Is it one person's secret?** Then it is a private actor on their account. Balances, ballots, badges, hands of cards, a ship's position.

**Is it a group's secret?** Then it is a group-owned private PDA. A hidden treasury, a shared ledger.

**Is it in transit?** Then it is a message. Value on its way to someone is a stored AsyncMessage, not a field in somebody's state.

## Mixed placements in one program

Most interesting programs use two placements and connect them with messages.

- **Public hub, private spokes.** A public actor holds the shared state. Each participant holds a private actor of the same program. Spokes speak to the hub with proof-carrying messages (pattern 7). The hub speaks to spokes with AsyncMessages (pattern 9). Voting, credentials and the space game have this shape.
- **Private hub, any spokes.** A group-owned private PDA holds the shared state. Participants send it AsyncMessages. One member at a time collects them. The hidden multisig has this shape.

The same program can support both, if its members always speak by AsyncMessage and its hub never assumes it is public. The [multisig](../catalog/multisig.md) entry works this through.

## A note on "who can read"

- Reading a public actor from off chain is free. Reading it from a **program** takes a request and a reply (pattern 5).
- A private actor is read by its owner's wallet. No program other than its own handler ever sees it.
- A sealed message is read by its recipient's wallet, before any handler runs. The wallet is the first line of defence against unwanted messages.
