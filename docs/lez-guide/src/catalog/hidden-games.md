# Battleship: players who cannot lie

**Shows:** the proof-carrying message (7) · the seat (4) · the public referee (12) · reply with an echo (5)

## Goal

Two players hide their fleets and take turns shooting. Each must say truthfully whether a shot hit.

On most chains this needs a commitment at the start and a full reveal at the end, and a liar is only caught after the game. Here a player **cannot** answer falsely. The answer is computed by the game's handler from the player's real hidden fleet, inside a proof.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(match, battleship)` | the two boards' addresses, whose turn it is, the shot waiting for an answer, the results so far | public PDA |
| `(player, battleship)`: a board | the match it plays in, and the fleet | private, on each player's account |

The match is public because it is the referee. The boards are private because they are the secret.

## Messages

```rust
/// From a player to their own board.
enum Command {
    Place { game: Actor, fleet: Fleet },
    Fire { at: Square },
    Answer,
}

/// Between actors of the game.
enum Internal {
    Joined,                              // board -> match: take a seat
    Shot { at: Square },                 // board -> match
    WhatWasFired,                        // board -> match
    Incoming { at: Square },             // match -> board, as the reply
    Result { at: Square, hit: bool },    // board -> match
}
```

## The board's handler

```rust
// Every command: only the owner, and never a collected message.
let owner = input.is_authorized && input.from.is_none();

Command::Place { game, fleet } => {
    assert!(owner && fleet.is_legal(), "ships overlap or leave the grid");
    Response::set_state(write_once(&input.pre_state, encode(&(game, fleet))))
        .send_sync(game, &Internal::Joined)
}

Command::Fire { at } => { assert!(owner); Response::keep_state().send_sync(game, &Internal::Shot { at }) }

// "Answer" asks the match which square was fired at...
Command::Answer => { assert!(owner); Response::keep_state().send_sync(game, &Internal::WhatWasFired) }

// ...and the match replies in the same transaction.
Internal::Incoming { at } => {
    assert_eq!(input.from, Some(game), "only my match tells me about shots");
    let hit = fleet.occupies(at);
    Response::keep_state().send_sync(game, &Internal::Result { at, hit })
}
```

## The match's side

The match is bookkeeping, with one rule that carries the whole design: **it pins each board's address when the board joins, and afterwards accepts messages only from those two addresses.**

```rust
let board = input.from.filter(|_| input.from_own_program()).expect("not a board").account_id;
match message {
    Internal::Joined => game.take_free_seat(board),          // remember this address
    Internal::Shot { at } => { assert_eq!(board, game.shooter()); game.pending = Some(at); }
    Internal::WhatWasFired => { assert_eq!(board, game.defender()); /* reply Incoming */ }
    Internal::Result { at, hit } => { assert_eq!(board, game.defender()); /* record; swap turns */ }
}
```

## How it runs

{{#include ../diagrams/battleship-shot.svg}}

1. **Place.** Each player places a fleet on their own board. The handler checks that it is legal, writes it once, and takes a seat at the match.
2. **Fire.** The shooter's board sends `Shot` to the match.
3. **Answer.** The defender's board asks the match what was fired, receives `Incoming`, and sends back `Result`. All in one private transaction.

## What to notice

**The player does not choose `hit`.** The handler computes it from the stored fleet. A proof of any other answer does not exist.

**The seat is what makes the fleet the same fleet.** A player may own several private accounts, each with a different legal fleet. Without the pinned address, a defender could answer each shot from whichever board says "miss". The match accepts answers only from the address that joined, and the board behind that address wrote its fleet once.

**The board must present the same address every time.** A private actor chooses the address it presents with each message. The board has to reuse the one it joined with, so the player's wallet must keep that blinding factor for the whole game.

**The match never sees a fleet, and never needs a commitment to one.**

**The answer is one transaction with a conversation inside it.** The private board sends a SyncMessage to the public match, the match answers, the board sends again. The proof covers the board's two runs. The sequencer runs the match's two.

**The defender must be the one to act.** The match cannot push a shot into a private board. That is why the board *asks*.

> **Improvement over plan/apply.** The plan/apply version of this game publishes each board's account id on the match, to tie answers to the fleet placed at the start, and the defender has to be told which square was fired at and propose it. Here the match knows a board by an address that can be a pseudonym, and the board asks the match for the pending shot inside the same transaction.

## What leaks

Every shot and every result, as in the board game. The two boards' addresses. Never a fleet. Even the loser's surviving ships stay hidden when the game ends.

## Going further

- **Deadlines.** A defender who never answers stalls the game. Each player posts a bond with the match, and anyone can claim it for the other player once the answer is late.
- **Other games, same recipe.** A private actor per player for the secret, a public match as referee that pins each player's seat, every answer a message from that seat.
  - Card games: a card can only be played if it is in the hand, and only once. The hard part is dealing without a trusted dealer.
  - Wordle or Mastermind: the secret is written once before the first guess, so it cannot be adapted.
  - Strategy with fog of war: see [Deep Space Radio](radio.md).
- **What does not work: randomness from the chain.** A handler is deterministic. Dice need a commit-and-reveal between the players.
