# Battleship: players who cannot lie

## Goal

Two players hide their fleets and take turns shooting. Each must say truthfully whether a shot hit.

On most chains this needs a commitment at the start and a full reveal at the end, and a liar is caught only after the game. Here a player **cannot** answer falsely. The answer is a guard on the player's own private shard, checked inside their proof. A proof of a false answer does not exist.

The entry uses two-sided binding (pattern 2) between a private shard and a public one, and binds accounts by content (pattern 17).

## Accounts

| Account | Placement | Contents |
|---|---|---|
| Match | a public account | `Match { boards: [AccountId; 2], turn: u8, pending: Option<Square>, results: Vec<(Square, bool)> }` |
| Board, one per player | **private**, the player's own | `Board { fleet }`, written once |

The match is public because both players write to it. The boards are private because they are the secret.

The match stores each board's **account id**. A private account id says nothing about its owner or its contents, and it is what ties every later answer to the fleet that was placed at the start.

## Instructions and effects

```rust
enum Instruction {
    Join   { fleet: Fleet },
    Fire   { at: Square },
    Answer { at: Square, hit: bool },
}
enum Effect {
    // On a board.
    Place(Fleet),                         // write once; the fleet must be legal
    Occupies { at: Square, hit: bool },   // guard: is `hit` the truth?

    // On the match.
    Seat { board: AccountId },            // take a free seat
    Shot { by: AccountId, at: Square },   // guard: it is `by`'s turn
    Result { by: AccountId, at: Square, hit: bool },   // guard: see below
}
```

## A simple version

```rust
fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    // accounts, always: the player's board, the match
    let [board, game] = <&[_; 2]>::try_from(input.accounts.as_slice()).unwrap();
    match ix {
        Instruction::Join { fleet } => {
            assert!(board.is_authorized, "join with a board you own");
            plan.effect(board, &Effect::Place(fleet));
            plan.effect(game, &Effect::Seat { board: board.account_id });
        }
        Instruction::Fire { at } => {
            assert!(board.is_authorized, "fire from your own board");
            plan.effect(game, &Effect::Shot { by: board.account_id, at });
        }
        Instruction::Answer { at, hit } => {
            assert!(board.is_authorized, "answer from your own board");
            plan.effect(board, &Effect::Occupies { at, hit });
            plan.effect(game, &Effect::Result { by: board.account_id, at, hit });
        }
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Place(fleet) => {
            assert!(fleet.is_legal(), "ships overlap or leave the grid");
            Some(write_once(pre_data, fleet.to_bytes()))
        }
        Effect::Occupies { at, hit } => {
            let truth = Fleet::from_bytes(pre_data).occupies(at);
            assert_eq!(truth, hit, "that is not the truth");
            None
        }
        Effect::Result { by, at, hit } => {
            let mut m = Match::from_bytes(pre_data);
            assert_eq!(by, m.boards[m.defender()], "not the defender's board");
            assert_eq!(m.pending, Some(at), "not the shot that was fired");
            m.results.push((at, hit));
            m.pending = None;
            m.turn ^= 1;
            Some(m.to_bytes())
        }
        Effect::Seat { board } => { /* fill the first empty seat */ }
        Effect::Shot { by, at } => { /* check the turn; set `pending` */ }
    }
}
```

{{#include ../diagrams/battleship-shot.svg}}

## Why the answer is honest

`Answer` emits two effects that carry the same `(at, hit)`.

- **`Occupies` runs in the defender's proof**, against their real board. If `hit` is not the truth, the proof cannot be made.
- **`Result` runs at settlement**, on the public match. It accepts the answer only from the board that took the defender's seat when the game began, and only for the shot that is pending.

Both effects come from one `plan`, and the plan is proven, so the answer recorded on the match is the answer the board gave. The board cannot be swapped, because the match pinned its id at `Join`. The fleet cannot be moved, because `Place` writes once.

The defender does not choose `hit`. They propose it, and only the true value survives.

**Why every instruction checks `board.is_authorized`.** `plan` sees an account id and a flag, not whether the account is public or private. Without the check, a defender could list their board's id as an ordinary *public* account. The `Occupies` guard would then run at settlement against an empty public shard instead of the real fleet. An authorized private account can only be supplied by its owner, with the real contents, and the circuit enforces the flag.

Each move also replaces the board's note, even when the board is only read, because a private account that takes part in a transaction is always re-committed.

> **With actors.** The match does not store the boards' account ids: it knows each board by an address that can be a pseudonym. The defender is not told the pending shot either. The board asks the match and is answered inside the same transaction.

## What the chain sees

Every shot and every result, as in the board game. The two board ids. Never a fleet, not even the loser's surviving ships when the game ends.

## Interoperability matrix

| Player's board | Works | Notes |
|---|---|---|
| Priv | yes | as described; each move is a private transaction |
| Pub | technically | the fleet is readable by everyone, which defeats the game |

| Match | Works | Notes |
|---|---|---|
| Pub | yes | required: both players write to it |
| Priv, group key | for friends | single-writer, which a turn-based game is anyway; nobody outside can referee |

## Variations and ideas

- **Deadlines.** A defender who never answers stalls the game. Each player posts a bond at `Join`, and a `Claim` instruction with a clock guard pays both bonds to the shooter when the answer is late.
- **Other games, same recipe.** A private account per player for the secret, a public match for turns, and every answer a guard on the private shard paired with an effect on the match.
  - Card games: `Play(card)` guards that the card is in the hand and removes it. The hard part is dealing without a trusted dealer.
  - Wordle or Mastermind: the secret is written once before the first guess, so it cannot be adapted.
  - [LeZork](lezork.md) and [Deep Space Radio](radio.md) for games with a map.
- **What does not work:** randomness from the chain. A program is deterministic. Dice need a commit-and-reveal between the players, with bonds.
