# Deep Space Radio: a game of private ships

**Shows:** every pattern at once, with different names

## Goal

A space game. Every player commands a ship whose position and cargo are hidden from everyone else. Stations are public places. Players talk by radio, and radio can carry cargo.

The game is in the catalog because each game mechanic is a protocol feature under another name:

| In the game | In the protocol |
|---|---|
| a ship | a private actor |
| fog of war | private state |
| the laws of physics | the handler, proven on every move |
| a station | a public actor |
| a radio message | an AsyncMessage |
| an encrypted channel | a sealed AsyncMessage from a private sender |
| a call sign | a blinded address |
| accepting a trade | collecting a message with the spending key |
| docking | a SyncMessage from private to public |

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(player, space)`: a ship | position, cargo, time of last move | private |
| `(station, space)` | its location, the call signs docked there | public PDA |

## Messages

```rust
/// From the player to their own ship.
enum Command {
    Move { to: Position, now: Timestamp },
    Radio { to: AccountId, text: String, cargo: u64 },
    Dock { station: AccountId },
}

/// Between actors of the game.
enum Internal {
    Signal { text: String, cargo: u64 },
    Docking { at: Position },
}
```

## Movement: the laws of physics are a handler

```rust
Command::Move { to, now } => {
    assert!(input.is_authorized && input.from.is_none(), "only the captain commands");
    let mut ship = Ship::from_bytes(&input.pre_state);
    let elapsed = now - ship.last_move;
    assert!(ship.position.distance(&to) <= elapsed * MAX_SPEED, "too far, too fast");
    ship.position = to;
    ship.last_move = now;
    Response::set_state(ship.to_bytes())
        .timestamp_window(now..)        // `now` cannot be in the future
}
```

Nobody sees the move. A move that breaks the speed limit cannot be proven, so it cannot happen.

Every command checks that it comes from the captain and from nobody else. Without that check, a stranger could send `Command::Radio { to: thief, cargo: everything }` to the ship and hope its captain collects it.

## Radio

```rust
Command::Radio { to, text, cargo } => {
    assert!(input.is_authorized && input.from.is_none(), "only the captain commands");
    let mut ship = Ship::from_bytes(&input.pre_state);
    ship.cargo = ship.cargo.checked_sub(cargo).expect("you do not carry that much");
    Response::set_state(ship.to_bytes())
        .send_async(Actor::new(to, me.program_account_id), &Internal::Signal { text, cargo })
}

// On the receiving ship, when its captain collects the message:
Internal::Signal { cargo, .. } => {
    assert!(input.from_own_program(), "not a ship");
    let mut ship = Ship::from_bytes(&input.pre_state);
    ship.cargo += cargo;
    Response::set_state(ship.to_bytes())
}
```

{{#include ../diagrams/radio-messages.svg}}

Different ways to use the same two arms:

- **Encrypted, ship to ship.** The sender is private, so the AsyncMessage is sealed. Only the recipient reads it, and nobody can tell who is talking to whom.
- **Call signs.** The ship sends under a blinded address. Observers and stations see a call sign and cannot link two call signs of one ship. A ship that wants a *reply* must give the other captain its keys and the factor behind the call sign, and that captain then knows which ship it is. Call signs hide a ship from the galaxy, not from the ships it chooses to talk with.
- **Distress call.** A `Signal` under a call sign that is never used again.
- **Cargo pod.** A `Signal` with cargo. The sender's hold shrinks when it is sent, and the receiver's grows when it is collected. Uncollected cargo drifts in space.
- **Listening is free, answering is a choice.** The captain's wallet reads every message. The ship only changes when the captain collects one.

> **Improvement over plan/apply.** A radio message used to be a separate "pod" account under the recipient's key, which the recipient moved into their ship with another instruction. Now the message is addressed to the ship, and the ship's own handler receives it. Call signs come from the protocol instead of hashes of secrets.

## Docking: proving where you are

```rust
Command::Dock { station } => {
    assert!(input.is_authorized && input.from.is_none(), "only the captain commands");
    let ship = Ship::from_bytes(&input.pre_state);
    Response::keep_state()
        .send_sync(Actor::new(station, me.program_account_id), &Internal::Docking { at: ship.position })
}

// On the station:
Internal::Docking { at } => {
    assert!(input.from_own_program(), "not a ship");
    assert_eq!(at, station.location, "you are not here");
    station.docked.push(input.from.unwrap().account_id);   // a call sign
    Response::set_state(station.to_bytes())
}
```

The station is public. It learns that **a real ship is at its dock**, under a call sign. It does not learn which ship, where it came from, or what it carries. The ship cannot lie about its position: `at` is read from its state by the game's own code, inside the proof.

Docking is the one moment a ship reveals where it is. That is the player's choice to make.

## What an observer sees

| Event | On chain |
|---|---|
| a move | a private transaction: unlinkable notes |
| ship-to-ship radio | a sealed message |
| docking | the station, a call sign, the dock's position |

## Going further

- **Trading.** An offer is a `Signal` that asks for something back. The other captain accepts by collecting it with their spending key (pattern 10).
- **Broadcasts.** A public beacon actor that logs what ships send it.
- **Combat.** Nobody can make a ship collect a torpedo. So contested space needs a public referee holding bonds (pattern 12): a challenged call sign answers "hit" or "miss" in time, by a message its handler computes from the real position, or it loses the bond.
- **Fleets.** A fleet is a private account owned by a group (pattern 18). Any officer can move it.

## What does not work

- **Real time.** Every action is a proof. The game suits minutes per move.
- **Automatic detection.** Two ships at the same place do not know it until one of them acts.
