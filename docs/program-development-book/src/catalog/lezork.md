# LeZork: a text adventure in accounts

## Goal

A multiplayer text adventure where every room is an account, every player's position and inventory is a private account, and the game logic is one small interpreter program. Authors add rooms by writing accounts; players explore without the chain learning where they are; items are contended in the open; puzzles are solved with secrets that never touch the chain. It is a toy, and it exercises nearly every pattern in the book in a setting where the trade-offs are easy to see.

## World model

| Thing | Account | Shard contents |
|---|---|---|
| Room | any account the author chooses (public for a shared world, private for a group's) | `Room { world: AccountId, id: RoomId, title, text, exits: Vec<(Direction, RoomId)>, items: Vec<ItemId>, locks: Vec<(Direction, ItemId)>, riddles: Vec<(Direction, [u8;32])>, notes: Vec<Vec<u8>> }` |
| World | any account the author chooses | `World { author: Authority, rooms_root: Option<[u8;32]>, start: RoomId }` |
| Player | private PDA `for_private_pda(game, H("player"), player_npk, player_vpk, Identifier::ZERO)` | `Player { world: AccountId, room: RoomId, inventory: Vec<ItemId>, score: u64 }` |
| Scoreboard | public PDA `H("score", world_id)` | `Vec<(tag, score)>` |

Rooms are up to 100 KiB each, which is a lot of prose. The author writes them with `write_once` (a fixed world) or with an authority (`Edit` gated on `author.is_authorized`). A room records which world it belongs to and its own id, so the program never needs to compute a room's address: the room says what it is, and the player's record says where they are, and the two are joined by the proposal in the instruction ([pattern 17](../patterns/index.md)).

The player is a private PDA of the game program under the player's own key: the player's wallet can see it and sync it, only the game program can authorize changes to it (by its seed), and nobody else can read it. Position and inventory are private. The player initializes it with `Enter`, which anyone can do for their own key.

## Instructions and effects

```rust
enum Direction { North, South, East, West, Up, Down }
enum Instruction {
    Enter { world_id },
    Go    { from: RoomId, dir: Direction, to: RoomId },
    Take  { world_id, room: RoomId, item: ItemId },
    Drop  { world_id, room: RoomId, item: ItemId },
    Say   { world_id, room: RoomId, dir: Direction, word: Vec<u8>, to: RoomId }, // riddle-locked exit
    Write { world_id, room: RoomId, note: Vec<u8> },                            // graffiti
    Score { world_id, tag: [u8;32], points: u64 },
}
enum Effect {
    // on a room (public, this program's shard)
    ExitLeadsTo { world: AccountId, from: RoomId, dir: Direction, to: RoomId, key: Option<ItemId> }, // guard: this is room `from` of `world`, exit exists, lock matches
    RiddleAnswerIs { dir: Direction, hash: [u8;32], to: RoomId },    // guard: hash matches
    RemoveItem(ItemId),                                             // write: item present -> removed
    AddItem(ItemId),                                                // write
    AppendNote(Vec<u8>),                                            // write
    // on the player (private, this program's shard)
    Spawn { start: RoomId },                                        // write once
    MoveFromTo { world: AccountId, from: RoomId, to: RoomId, needs: Option<ItemId> }, // guard: same world, room == from, has key; write room = to
    Pickup { at: RoomId, item: ItemId },                            // guard: room == at; write inventory
    PutDown { at: RoomId, item: ItemId },                           // guard: has item; write
    AddScore(u64),
    // on the scoreboard (public)
    Post { tag: [u8;32], points: u64 },
}
```

## A simple version of `Go`

```rust
Instruction::Go { from, dir, to } => {
    // accounts: world (public or private), from-room (same placement), player (private PDA)
    let [world, room, player] = <&[_; 3]>::try_from(input.accounts.as_slice()).unwrap();
    // The plan cannot read the room, so it proposes the exit and lets the room confirm it,
    // and proposes the move and lets the player's own shard confirm the origin. The world's
    // account id, taken from the handle, is what ties the two records together.
    plan.effect(room,   &Effect::ExitLeadsTo { world: world.account_id, from, dir, to, key: None });
    plan.effect(player, &Effect::MoveFromTo  { world: world.account_id, from, to, needs: None });
}
// apply, room side
Effect::ExitLeadsTo { world, from, dir, to, key } => {
    let r = Room::from_bytes(pre_data);
    assert_eq!((r.world, r.id), (world, from), "that is not the room you are in");
    assert!(r.exits.contains(&(dir, to)), "you can't go that way");
    assert_eq!(r.locks.iter().find(|(d, _)| *d == dir).map(|(_, k)| *k), key, "the door is locked");
    None
}
// apply, player side
Effect::MoveFromTo { world, from, to, needs } => {
    let mut p = Player::from_bytes(pre_data);
    assert_eq!((p.world, p.room), (world, from), "you are not there");
    if let Some(k) = needs { assert!(p.inventory.contains(&k), "you don't have the key"); }
    p.room = to;
    Some(p.to_bytes())
}
```

A locked door is the same with `key: Some(item)` on both effects: the room confirms the lock wants that item, the player confirms they carry it. The two applies never see each other; the proposal `(dir, to, key)` is the join.

`Take` is `RemoveItem` on the room (a **write** to public state) plus `Pickup` on the player. If two players grab the same item in one block, the room's effects apply in order and the second `RemoveItem` panics: their transaction is refused, nothing else in it happens, and they can try the next room. Contended items are the multiplayer part.

`Say` is pattern 11: the riddle's answer is in the instruction of a private transaction; the plan hashes it and the room's guard compares hashes. The answer is never published. Other players see only that *someone* passed the riddle door (the guard effect names the room and the direction).

## What the chain sees

Every move is a private transaction with two real notes at most (the player PDA; plus a private item vault if you keep items private) and public effects on rooms:

- `Go`: `ExitLeadsTo { dir, to, key }` on the from-room. So: *someone* went from room X to room Y, and whether they used a key. Not who. With many players this is a heat map of the world, not a track of a person.
- `Take`/`Drop`/`Write`: the room's item list or notes change, visibly. Graffiti is public by nature.
- `Say`: a guard on a room naming a direction and the riddle hash (already in the room).
- `Score`: a tag and points on the board.

Player position, inventory and score are never on chain except as the player chooses to post to the board under a tag.

{{#include ../diagrams/lezork-moves.svg}}

## Making movement invisible

The `ExitLeadsTo` guard is a public effect on a specific room, which is what leaks the edge. To hide even that, put a **Merkle root of all rooms** in the world account and let the player carry room data in instruction data:

```rust
Instruction::GoBlind { world_id, from_room_bytes: Vec<u8>, path: Vec<([u8;32], bool)>, dir, to }
// plan: root = merkle_root(H(from_room_bytes), &path); assert exit in decoded room;
//       plan.effect(world, &Effect::RoomsRootIs(root));   // one guard on the world account
//       plan.effect(player, &Effect::MoveFromTo { .. });
```

Now every move publishes the same guard on the same account (`RoomsRootIs(root)`), and the chain learns that a move happened, nothing about where. The price: the world is static (a root), so items cannot be taken from rooms this way; keep `Take` on live rooms and `Go` on the root, or version the root by author edits.

## Fully private worlds

A **shadow program** version puts the entire world into the player's private PDA as a save file and runs the interpreter with no public effects at all: single player, nothing on chain but nullifiers, and not even the program's existence disclosed. A **group-key** version shares one private world among a party: hidden from everyone else, but single-writer, so the party takes turns, which for a dungeon crawl is arguably the right rule.

## Interoperability matrix

| Rooms | Player | Items | Chain sees | Multiplayer |
|---|---|---|---|---|
| Pub | Priv | in rooms (pub) | edges travelled, item movements | yes, contended items |
| Pub, Merkle root | Priv | none, or in a separate public layer | that moves happen | yes for the item layer only |
| Priv (group) | Priv | private | nothing | turn-based party |
| Priv (shadow) | Priv | private | nothing, no claim | single player |
| Pub | Pub | pub | everything | yes; a public MUD |

## Ideas

- **Player-versus-player**: a `Duel` between two players needs both private PDAs in one transaction, which needs both witnesses: impossible across wallets. Route it through a public arena room: each player posts a commitment, then reveals, the room's apply decides. Or a pairwise group key for the two duellists.
- **Timed events**: doors that open after `T` are a clock guard on the room: `ExitOpenAfter { dir, t }`.
- **NPC shops**: an item vault as a token holding in a room PDA; `Buy` chains `token::Transfer` from the player's private token holding into the shop's public one and `AddItem` to the player. Price public, buyer hidden.
- **Persistent achievements**: an NFT printed into the player's private account by the game program when a guard on the player's shard confirms the condition; the player can later prove it (see [attestations](access-and-attestations.md)) without revealing anything else about their run.
- **Author economics**: room writes are charged public transactions today; a 100 KiB room is 100 KiB of storage gas. Private moves are free (interim), which is either delightful or a spam problem depending on the day.
