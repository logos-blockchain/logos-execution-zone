# Deep Space Radio: a game of private ships

## Goal

A space game. Every player commands a ship whose position and cargo are hidden from everyone else. Stations are public places. Players talk by radio, and radio can carry cargo.

The game is in the catalog because each game mechanic is a protocol feature under another name:

| In the game | In the protocol |
|---|---|
| a ship | a private account |
| fog of war | private state |
| the laws of physics | a guard in `apply`, proven on every move |
| a station | a public account |
| a radio message | a fresh private slot under the recipient's key (pattern 9, init-only receive) |
| taking cargo aboard | the recipient moving a received slot into their ship |
| docking | a guard on the private ship paired with an effect on the public station (pattern 2) |

## Accounts

| Account | Placement | Contents |
|---|---|---|
| Ship | **private**, the player's own | `Ship { position, cargo, last_move_ms }` |
| Pod | a fresh **private** slot under the recipient's key | `Pod { text, cargo }`, written once by the sender |
| Station | a public account | `Station { location, docked: u64 }` |

A ship and a pod are both shards of the game program. A tag in the data tells them apart. Ships are created by a `Launch` at a station and cargo enters the game by mining or buying there; neither is shown.

## Instructions and effects

```rust
enum Instruction {
    Move  { to: Position, now_ms: u64 },
    Radio { text: String, cargo: u64 },
    Take  { cargo: u64 },
    Dock  { at: Position },
}
enum Effect {
    // on a ship
    MoveTo { to: Position, now_ms: u64 },   // guard: speed limit; then update
    Unload(u64),                            // guard: enough cargo; then subtract
    Load(u64),                              // add
    IsAt(Position),                         // guard only
    // on a pod
    Deliver { text: String, cargo: u64 },   // write_once
    Empty   { cargo: u64 },                 // guard: the pod holds exactly this; then zero it
    // on a station
    Docked  { at: Position },               // guard: `at` is the station's location; count it
}
```

## A simple version

```rust
fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match ix {
        // accounts: my ship
        Instruction::Move { to, now_ms } => {
            let [ship] = <&[_; 1]>::try_from(input.accounts.as_slice()).unwrap();
            assert!(ship.is_authorized);
            plan.effect(ship, &Effect::MoveTo { to, now_ms });
            plan.timestamp_window(now_ms..);          // `now_ms` cannot be in the future
        }
        // accounts: my ship, a fresh slot under the recipient's key
        Instruction::Radio { text, cargo } => {
            let [ship, pod] = <&[_; 2]>::try_from(input.accounts.as_slice()).unwrap();
            assert!(ship.is_authorized);
            plan.effect(ship, &Effect::Unload(cargo));
            plan.effect(pod, &Effect::Deliver { text, cargo });
        }
        // accounts: a pod I received, my ship
        Instruction::Take { cargo } => {
            let [pod, ship] = <&[_; 2]>::try_from(input.accounts.as_slice()).unwrap();
            assert!(pod.is_authorized);
            plan.effect(pod, &Effect::Empty { cargo });
            plan.effect(ship, &Effect::Load(cargo));
        }
        // accounts: my ship, the station
        Instruction::Dock { at } => {
            let [ship, station] = <&[_; 2]>::try_from(input.accounts.as_slice()).unwrap();
            assert!(ship.is_authorized);          // a real private ship, not a public look-alike
            plan.effect(ship, &Effect::IsAt(at));
            plan.effect(station, &Effect::Docked { at });
        }
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::MoveTo { to, now_ms } => {
            let mut ship = Ship::from_bytes(pre_data);
            let elapsed = now_ms.checked_sub(ship.last_move_ms).expect("time runs forward");
            assert!(ship.position.distance(&to) <= elapsed * MAX_SPEED, "too far, too fast");
            ship.position = to;
            ship.last_move_ms = now_ms;
            Some(ship.to_bytes())
        }
        Effect::IsAt(at) => { assert_eq!(Ship::from_bytes(pre_data).position, at); None }
        Effect::Docked { at } => {
            let mut station = Station::from_bytes(pre_data);
            assert_eq!(station.location, at, "you are not here");
            station.docked += 1;
            Some(station.to_bytes())
        }
        Effect::Deliver { text, cargo } => Some(write_once(pre_data, Pod { text, cargo }.to_bytes())),
        /* Unload, Load, Empty: checked arithmetic on one shard each */
    }
}
```

{{#include ../diagrams/radio-messages.svg}}

## What to notice

**Movement.** Nobody sees the move. A move that breaks the speed limit cannot be proven, so it cannot happen. The validity window stops a player from claiming a time that has not come.

**Radio.** The sender cannot write to the recipient's ship: updating a private account needs its owner's key. So a message is a **new** private account under the recipient's key, which anyone may initialize. Only the recipient can read it. The chain sees a note and cannot tell who is talking to whom.

**Cargo.** `Unload` on the sender's ship and `Deliver` on the pod carry the same amount, so cargo is conserved. The cargo is aboard the recipient's ship only after they run `Take`. An untaken pod drifts in space.

**Listening is free, answering is a choice.** The recipient's wallet decrypts every pod. The ship changes only when its captain takes one.

**Docking.** `IsAt` runs in the ship's proof, against its real position. `Docked` runs at settlement, on the public station, with the same position. The station learns that a real ship is at its dock. It does not learn which ship, where it came from, or what it carries.

Docking is the one moment a ship reveals where it is. That is the player's choice.

`Dock` requires the ship to be authorized for the same reason as in [Battleship](battleship.md): otherwise the `IsAt` guard could be pointed at a public account with made-up contents.

> **With actors.** A message is delivered to the ship itself, so there is no pod account and no `Take`. A ship also gets call signs from the protocol: blinded addresses that others can reply to.

## What the chain sees

| Event | On chain |
|---|---|
| a move | a private transaction, and a validity window starting at `now_ms` |
| ship-to-ship radio | a private transaction; one of its notes is the pod |
| taking cargo | a private transaction |
| docking | the station and its location, as a public effect |

A pod's note carries a one-byte view tag derived from the recipient's keys, so pods to the same ship are weakly correlated. The station's `Docked` effect is applied by whatever code is deployed at the game's address when the transaction settles, so deploy the game immutable.

The game program is named in the claims of every one of these, unless it is deployed immutable and run undisclosed. An undisclosed program cannot dock, because a public effect names its program.

## Interoperability matrix

| Ship | Station | Works | Notes |
|---|---|---|---|
| Priv | Pub | yes | as described |
| Pub | Pub | yes | an ordinary on-chain game: everything visible |
| Priv | Priv, group key | among friends | the station's keepers must take turns writing it |

## Variations and ideas

- **Call signs.** A ship that wants a stable name at stations carries a secret and docks with its hash (pattern 11). Different secrets give unlinkable names.
- **Trading.** A pod can ask for something back. The simplest fair trade goes through a public escrow, as in [Escrow](escrow-auctions.md).
- **Combat.** Nobody can make a ship answer a torpedo. Contested space needs a public referee holding bonds: a challenged ship answers "hit" or "miss" in time, with an `IsAt`-style guard as in [Battleship](battleship.md), or loses the bond.
- **Fleets.** A ship held through a group key. Any officer can move it, one at a time.

## What does not work

- **Real time.** Every action is a proof.
- **Automatic detection.** Two ships at the same place do not know it until one of them acts.
- **Radio to a ship, into its hold directly.** Receiving is always a fresh slot first.
