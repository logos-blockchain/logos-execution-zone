# Private voting

## Goal

A registered set of voters, each voting at most once, with the outcome verifiable. Three privacy targets, of increasing difficulty: hide **who voted** (anonymity), hide **how each voter voted** (ballot secrecy), hide **the running tally** until the end. The account model handles the first two well with public tallies, and the third only by trusting a tallier or by serializing.

## The core difficulty

A tally is shared state written by many voters at once, so it has to be **public** (private state is single-writer). Every vote is then a public effect on it, and the effect bytes carry the choice. Ballot secrecy against the chain therefore cannot come from the tally; it has to come from breaking the link between the vote and the voter, or from moving the tally off chain.

## Design A: anonymous voters, public ballots

Voters register a credential `H(secret)`. To vote, a voter proves membership in a private transaction and increments a public counter; what the chain sees is a vote and a one-time nullifier, not a voter.

### Accounts

| Account | Placement | Contents |
|---|---|---|
| Election | any public account the organizer chooses | `Election { members_root: [u8;32], options: u8, start_ms, end_ms, tally: Vec<u128> }` |
| Ballot receipt | public PDA of the program with seed `nullifier = H("ballot", election.account_id, secret)` | one marker byte; public by design, so deriving its address in the plan is right |
| Clock | public | read-only |
| Voter | no account needed: the secret lives in instruction data | |

`members_root` is the root of a Merkle tree over the registered `H(secret)` values, computed off chain and written once by the organizer. The voter's transaction carries the Merkle path in instruction data.

### Instructions and effects

```rust
enum Instruction {
    Create { members_root: [u8;32], options: u8, start_ms: u64, end_ms: u64 },
    Vote   { secret: [u8;32], path: Vec<([u8;32], bool)>, choice: u8, now_ms: u64 },
}
enum Effect {
    CreateElection(Election),                 // write_once
    RootIsAndOpenAt { root: [u8;32], now_ms: u64, choice: u8 }, // guard+tally on the election
    TimestampIs(u64),                         // clock guard, exact or bounded
    CastOnce,                                 // receipt: refuse if non-empty
}
```

### A simple version

```rust
Instruction::Vote { secret, path, choice, now_ms } => {
    let [election, clock, receipt] = <&[_; 3]>::try_from(input.accounts.as_slice()).unwrap();
    // The election is whatever account was handed in; its own record (root, window) is the
    // guard. The receipt is keyed by the election's account id, so a ballot cannot be reused
    // across elections.
    let leaf = sha256(&secret);
    let root = merkle_root(leaf, &path);                    // computed in the proof
    let nullifier = sha256(&[b"ballot", election.account_id.as_ref(), &secret[..]].concat());
    assert_eq!(receipt.account_id, AccountId::for_public_pda(&me, &PdaSeed::new(nullifier)));  // public by design
    assert!(choice < MAX_OPTIONS);
    // the clock must be inside the window; use a bounded window rather than an exact time
    plan.inspect(clock, clock.program_account_id, &Effect::TimestampIs(now_ms));
    plan.timestamp_window(now_ms.saturating_sub(SLACK_MS)..now_ms + SLACK_MS);
    plan.effect(election, &Effect::RootIsAndOpenAt { root, now_ms, choice });
    plan.effect(receipt, &Effect::CastOnce);
}
// apply
Effect::RootIsAndOpenAt { root, now_ms, choice } => {
    let mut e = Election::from_bytes(pre_data);
    assert_eq!(e.members_root, root, "not a registered voter");
    assert!(e.start_ms <= now_ms && now_ms < e.end_ms, "election closed");
    e.tally[choice as usize] += 1;
    Some(e.to_bytes())
}
Effect::CastOnce => { assert!(pre_data.is_empty(), "already voted"); Some(vec![1]) }
```

The secret and the Merkle path never leave the prover: the instruction data of a private transaction is not published. The only public effects are `RootIsAndOpenAt { root, now, choice }` on the election and `CastOnce` on a receipt whose address is a hash of a value nobody else can compute. Two votes from the same secret produce the same receipt address and the second is refused at settlement.

The `TimestampIs` clock guard with an exact value is the wrong tool in a private transaction (it will rarely settle at exactly that millisecond); the sketch keeps it to show the shape but a real program uses `TimestampAtLeast(start)` plus `plan.timestamp_window(..end)` to bound the vote to the election period.

{{#include ../diagrams/voting-anonymous-voters.svg}}

> **With actors.** The Merkle tree of credentials, the membership path and the per-vote receipt account are not needed. A voter holds a ballot in a private account, and the tally accepts a vote because the voting program itself sent it.

### What it hides and what it does not

- Hidden: which registered voter cast which vote, and who has voted at all.
- Public: every vote's choice (in the tally effect), the running tally, the number of votes, and the registration root. Ballot secrecy holds only in aggregate: with 100 voters and 100 votes nothing is learned beyond the tally; with 2 voters, each vote is a coin flip an observer can weight by timing.
- The `choice` inside the public effect is the leak. It cannot be encrypted because the tally apply must read it.

## Design B: secret ballots, trusted tallier

Move the tally off chain into notes only the tallier can read, using **init-only receive** (pattern 9) as a ballot box.

- The organizer mints one **vote token** per voter (a fungible token with supply = electorate, or one NFT copy each) into each voter's private account. Distribution is `token::Transfer` from the organizer to fresh private slots under each voter's key.
- To vote for option `k`, a voter transfers their token to a **fresh private slot under the tallier's key** whose identifier encodes the choice: `identifier = H(election, k, random)`... except that identifiers are inside the note and the tallier learns the choice only by decrypting, which is exactly right. Simpler: the tallier publishes one key per option and the voter sends to option `k`'s key.
- After the election the tallier syncs, counts the tokens per option key, and publishes the result. To make the result verifiable the tallier proves it: a private transaction per batch of seven slots that inspects each one (`HoldsVoteToken`) and emits a public effect `Counted { option, n }` on the election record; the batches add up and each slot is nullified so it cannot be counted twice.

What the chain sees during voting: private token transfers, seven notes each, no public effects, the token program claim. Not who voted.

**The tally is not hidden, and this is a defect in the design rather than a caveat.** The tallier publishes one key per option, and an init note's view tag is one published byte, `H(npk ‖ vpk)[0]`, derived from the recipient's keys ([What a private transaction reveals](../privacy/what-leaks.md)). Each ballot opens a fresh slot under the option's key, so each ballot is an init note and carries a publicly computable tag identifying the option it went to. An observer buckets the private actions in the voting window by tag and reads off per-option counts, contaminated only by the roughly 1-in-256 collision rate from unrelated traffic. The same arithmetic is done earlier for a single key, in [private donations](donations.md), where it narrows "is this a donation to X" from 1 in N to 1 in N/256; here it is worse, because the keys are published by construction rather than merely public.

Nothing in this design hides the running tally. Treat Design B as hiding *who* voted, not *how the vote is going*. The "who" half does hold, and for a reason worth naming: a voter spends from their own existing private slot, which is an update, and update notes carry a random tag, so the organiser who minted the tokens cannot follow them. A fix needs ballots that do not carry a per-option recipient key, which this model has no primitive for: see [Design C](#design-c-hidden-tally-hidden-ballots-no-trust-not-available).

Trust: the tallier could refuse to count some ballots (it cannot forge them: it has no vote tokens). Voters cannot verify their own ballot was counted without the tallier revealing per-slot information. A committee tallier under a group key spreads the trust without changing the mechanics: the ballot slots are independent notes under the tallier key, the `Counted` effect on the public record commutes, and the group key is needed only to build the witnesses, so counting does not serialize on it.

Double voting is prevented by the token supply, not by receipts: a voter has one token.

{{#include ../diagrams/voting-secret-ballots.svg}}

## Design C: hidden tally, hidden ballots, no trust: not available

A tally that is both hidden and updated by many voters would be a private account with many writers. It is single-writer. The nearest approximations are Design B (trusted holder of the ballot box) and a sequential private tally (a group-key account each voter updates in turn, unworkable beyond a handful of voters). Homomorphic tallying inside effects is not possible either: an `apply` on a public shard runs in the clear on the sequencer with the effect bytes as its only input, so it cannot add an encrypted vote to an encrypted tally without the sequencer being able to do the same computation on any bytes it likes. That is not a decryption leak, but it means the tally's confidentiality would rest on a threshold decryption ceremony that LEZ has no primitive for.

## Interoperability matrix

| Voter's registration | Vote tx | Voter hidden | Choice hidden | Tally live |
|---|---|---|---|---|
| public account id, votes by signing (public tx) | public | no | no | yes |
| public account id, votes by signing a private tx | private | no (signature) | no | yes |
| secret credential, Design A | private | yes | no (in aggregate only) | yes |
| vote token in a private account, Design B | private | yes | no: the per-option view tag leaks it | yes: per-option counts are readable throughout |

## Ideas

- **Weighted voting** with Design A: the leaf commits to a weight, `leaf = H(secret ‖ weight)`, the effect carries the weight, the apply adds it. The weight is then public per vote.
- **Delegation** (liquid democracy) needs the delegate to prove the delegation, which is a second leaf set or a signed statement carried in instruction data and checked in the plan; workable in Design A.
- **Quadratic voting**: the plan computes the cost from the choice vector; a public effect debits a public vault; the vault debit reveals the cost and hence the intensity.
- **Elections over many blocks with prepared votes**: a voter can prove a vote days before the window and hand it to anyone to submit; validity windows enforce the period; the vote is a bearer object until submitted. Useful for voters without a node, dangerous for coercion (the holder can see the choice).
- **What does not work:** anonymous voting from a *public* registration list by public account ids. The membership proof is over credentials the voter can prove in zero knowledge; a public account id is proven by signature, which names the voter. To vote anonymously a voter needs a secret, so registration must hand out secrets (or let voters register `H(secret)` from their public account, which links the credential to the account at registration time but not at voting time, and is a fine compromise).
