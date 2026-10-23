# Private voting

**Shows:** the proof-carrying message (7) · pseudonym (8) · windows for expiry (16)

## Goal

An election where the list of eligible voters is public, the running tally is public, and nobody can tell how any voter voted, or whether they voted at all.

This is the reference use of the proof-carrying message (pattern 7): the public tally trusts a vote because it comes from its own program, running on hidden state it never sees.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(election, voting)` | the question, the deadline, the tally, a count of ballots issued | public PDA |
| `(voter, voting)`: a ballot | which election, and whether it has been used | private, on each voter's account |

## Messages

```rust
enum Message {
    /// To the election, by the organiser: send one ballot to each address.
    Open { voters: Vec<AccountId>, deadline: Timestamp },
    /// Election to voter: you may vote.
    Ballot,
    /// To a ballot, by its owner.
    CastVote { choice: u8 },
    /// Voter to election: one valid vote.
    Vote { choice: u8 },
}
```

## How it runs

{{#include ../diagrams/voting-anonymous.svg}}

**1. Open.** The organiser sends `Open` with the voters' addresses. The election actor sends one `Ballot` to each as an async message. These are stored messages from a public actor: everyone can see who is eligible.

**2. Collect the ballot.** Each voter collects their `Ballot`. Their private ballot actor checks that it comes from the voting program, and records the election.

**3. Vote.** The voter sends `CastVote` to their ballot actor in a private transaction. The handler checks that the ballot is unused, marks it used, and sends `Vote` to the election under a fresh blinded address.

**4. Tally.** The election's handler checks `from_own_program()` and the deadline, and adds one to the chosen option.

## Handler

```rust
fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let me = input.receiver;
    match message {
        // Voter side: receive the ballot. Only an election of this program can issue one.
        Message::Ballot => {
            let election = input.from.filter(|_| input.from_own_program()).expect("not a ballot");
            Response::set_state(write_once(&input.pre_state, encode(&(election, false))))
        }

        // Voter side: use the ballot. Only the owner can, and only once.
        Message::CastVote { choice } => {
            assert!(input.is_authorized && input.from.is_none());
            let (election, used): (Actor, bool) = decode(&input.pre_state);
            assert!(!used, "already voted");
            Response::set_state(encode(&(election, true)))
                .send_sync(election, &Message::Vote { choice })
        }

        // Election side: count. The sender is a ballot actor of this program.
        Message::Vote { choice } => {
            assert!(input.from_own_program(), "not a ballot");
            let mut election = Election::from_bytes(&input.pre_state);
            election.tally[choice as usize] += 1;
            Response::set_state(election.to_bytes())
                .timestamp_window(..election.deadline)
        }

        Message::Open { voters, deadline } => /* store the deadline; send `Ballot` to each voter as an async message */,
    }
}
```

## Why a voter cannot cheat

- **Vote without a ballot.** The ballot actor's state is empty, so `CastVote` fails. A ballot state can only be written by a `Ballot` from the voting program.
- **Vote twice.** `used` is true after the first vote. The second run starts from that state, because the proof ties each run to the account's real, latest state.
- **Forge a `Vote` directly.** The election accepts `Vote` only from an actor of the voting program. The only code path in the voting program that sends `Vote` is the one above.
- **Use someone else's ballot.** A ballot is state on the voter's own private account. Nobody else can run its handler.

The election never checks a signature, a membership proof or a nullifier. All of that is done by the engine.

> **Improvement over plan/apply.** The earlier design needed a Merkle tree of registered secrets, a membership path in every vote, and a public receipt account per vote to stop double voting. All three are gone. Eligibility is holding a ballot, and voting twice is impossible because the ballot's own state says it was used.

## What leaks

| Observer learns | Yes or no |
|---|---|
| who is eligible | yes |
| the tally, live | yes |
| that some ballot voted for option X at time T | yes |
| which voter that was | no |
| whether a given voter has voted | no |
| whether a given voter collected their ballot | no |

Timing is the remaining risk. In a small election, a vote that appears seconds after one voter comes online is a strong hint.

## Placements

| Voter | Works | Notes |
|---|---|---|
| Private | yes | as described |
| Public | yes | their vote is public: the ballot actor is public state and the vote is a signed transaction |

The program does not care. A voter who wants an open vote uses a public account.

{{#include ../diagrams/voting-public-voter.svg}}

A public voter's ballot cannot be stored: only private addresses have a mailbox. The organiser's `Open` transaction has to declare each public voter's ballot actor so the ballot is delivered at once. If one is missing, the whole `Open` fails.

## Going further

- **Hidden tally until the end.** Votes carry a commitment, opened after the deadline by a second message.
- **Delegation.** A voter forwards their ballot to a delegate's address.
- **What does not work: coercion resistance.** A voter can prove how they voted by showing their transaction and its secrets.
