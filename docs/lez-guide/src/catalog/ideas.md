# Idea catalog: more designs, and what does not work

Shorter designs, each in a few lines: what it is, which patterns it uses, and the catch. Patterns are numbered as in [The pattern language](../patterns/index.md). The second half lists things that do not fit the model, with the reason.

## Money

**Payroll.** A company PDA holds the month's salaries. One public transaction sends a credit to each employee's address as an async message. Employees collect privately. Amounts are public unless the payroll actor is group-owned and private, in which case an officer runs it and the async messages are sealed. *(9, 13, 18)*

**Tip jar.** A creator publishes one blinded address per platform. Tips are plain transfers. *(9, 8)*

**Savings lock.** A PDA vault that pays its owner's address only after a date. The owner cannot break it, because no key controls a PDA. *(13, 17)*

**Allowance for a child account.** A mandate actor on the parent's account that accepts bills from one address up to a limit per period. See [Payment requests](requests.md). *(10)*

**Crowdfunding with a threshold.** A public campaign PDA collects deposits under pseudonyms. At the deadline, anyone pokes it: if the goal is met it pays the creator, otherwise it sends each deposit back to the address it came from as an async message. Backers stay hidden, the total is public. *(8, 11, 13)*

**Private lending between friends.** A group-owned private ledger. No enforcement beyond the group. *(18)*

**Bounties.** A public PDA holds a reward and a hash. The first message carrying the preimage is paid at the address it names. To stop front-running, the claim first commits to the answer and the claimant's address, then reveals. *(13, 14)*

## Governance

**Anonymous feedback box.** A public actor that accepts one message per badge per period. *(7, 8, rate limit from [Credentials](credentials.md))*

**Petition.** Signers are private. The petition counts proof-carrying signatures, one per badge. The count is public, the signers are not. *(7)*

**Council with secret ballots and public members.** The council list is public. Votes go through private seats under fresh addresses. Everyone knows who may vote, nobody knows how each voted. *(7, 8)*

**Whistleblower channel.** A newsroom publishes its keys. A source sends a sealed message from a throwaway private account, with a bond. To be answered, the source includes that account's keys, so the newsroom can seal a reply to it. The newsroom learns one throwaway account and nothing else. *(8, 9)*

**Jury selection.** Jurors hold badges. A case actor picks jurors by pseudonym from those who volunteered. Jurors vote under the same pseudonym for the case and are paid at it. *(7, 8, 12)*

## Identity and access

**Age check.** See [Credentials](credentials.md). *(7)*

**Allow-listed token sale.** The sale accepts purchases only with an `Attested` message from a badge, limited to one per badge. *(7)*

**Anonymous forum karma.** A forum sends karma badges to pseudonyms as async messages. Users collect them into their account and show a total under a new pseudonym. *(7, 8, 9)*

**Guest list with plus-ones.** A transferable ticket that can be split once. *(7)*

**Private key rotation.** A private actor that forwards everything it receives to a new address, written once. Old addresses keep working. *(15)*

## Coordination and games

**Secret Santa.** A public organiser actor assigns each participant another participant's address without learning who is behind any address. A gift sent from a public account needs only the address. A gift sent privately needs the recipient's keys, so that giver learns the recipient's account. *(8, 9)*

**Prediction market with hidden positions.** The market and its prices are public. Positions are private actors. Buying and redeeming cross the boundary under pseudonyms. *(7, 8, 13)*

**Treasure hunt.** Clues are stored messages sealed to whoever solved the previous clue. *(9)*

**Turn-based strategy.** See [Deep Space Radio](radio.md) and [Hidden-information games](hidden-games.md).

**Correspondence chess with a clock.** A public match actor, validity windows for each move's deadline. *(12, 16)*

## Infrastructure

**A `Stamp` message for the clock.** Today a program can only assert a time range. A request and reply would let it **read** the time (pattern 5):

```rust
// to the clock, from any actor
Stamp { granularity: Granularity, payload: Vec<u8> }
// reply to the sender
Stamped { block_id: u64, timestamp: Timestamp, payload: Vec<u8> }
```

The `granularity` matters for private callers: a reply that names the latest block is stale one block later, and a reply rounded to fifty blocks stays valid for fifty. With this, one clock actor that stores the last three rounded readings could replace the three clock accounts. This is a proposal, not a shipped feature.

**Keeper network.** A registry of pokable actors and the fee each pays. Keepers earn by sending the transactions nobody else bothers to send. *(11)*

**Relayer for private fees.** When private transactions pay fees, a public relayer can pay them and be repaid by an AsyncMessage inside the same transaction. *(9)*

**Message board with expiry.** A public actor that keeps the last N messages and drops older ones, so its state stays bounded.

**Name registry.** A public actor per name, derived from the name's hash (pattern 14). It holds an address. Paying "alice" means reading the address and sending to it. A private owner updates the address under a pseudonym.

**Notification inbox.** A user's private actor that accepts `Notify { topic, text }` from anyone and never acts on it. Wallets read notifications without collecting them. Programs get a standard way to tell a private user something.

## What does not work, and why

**An automated market maker with hidden reserves.** Trading needs the reserves. Whoever trades must see them, so they are public, or one party holds the keys and must run every trade.

**A private order book matched by the chain.** Matching compares two parties' secrets. No single transaction can run both parties' private handlers.

**Liquidating a private position.** Nobody can run a private handler but its owner. Collateral that must be seizable has to sit in a public actor.

**Reading someone's private balance with their permission.** There is no view grant in the protocol. The owner can share their viewing key, which shows everything, or prove a specific claim about the balance with a badge-style program.

**Private recurring payments with the payer offline.** A private account does nothing while its owner is away. Pre-fund a public stream.

**Refunding a stored credit automatically.** A stored message cannot bounce. The sender needs a return path in the program: a deadline after which they may reclaim, enforced by a public actor.

**A program that scans the mailbox.** Handlers see one message. Scanning is done by wallets, off chain.

**Guaranteed delivery.** An AsyncMessage guarantees that the message is stored, never that it is collected.

**Randomness.** No beacon exists. Two parties can produce a shared random value by commit and reveal. A single party cannot produce one that others trust.

**Hiding that you use a program.** A disclosed program is named in every private transaction that runs it. Only immutable programs can run undisclosed.

**Unbounded fan-out to private recipients.** Each recipient pays a proof per message. A design that sends a thousand people a message a day will be ignored by most of them.
