# Where state lives

The first design decision for any program is where each piece of state goes. The placement decides who can read it, who can write it, how many parties can write it at once, and what a transaction reveals when it touches it. This table is the whole trade-off space.

| Placement | Address | Who sees it | Who can write (given the program agrees) | Concurrent writers | Touching it in a private tx reveals |
|---|---|---|---|---|---|
| Public key-held account | `H(pubkey)` | everyone | the key holder (signature) or a program with an authorized handle | many | the account id and the effect bytes |
| Public PDA | `for_public_pda(program, seed)` | everyone | only the program, by seed delegation | many | same |
| Private regular account | `H(npk, vpk, id)` | `vsk` holder | initialize: anyone, once; update: `nsk` holder (authorized only with `ask`) | one per commitment | nothing (a nullifier and a commitment) |
| Private PDA | `for_private_pda(program, seed, npk, vpk, id)` | `vsk` holder | initialize: anyone; update: `nsk` holder; authorized only by the program's seed | one per commitment | nothing |
| Private PDA family | same, over all `id` | `vsk` holder | as above, one slot per `id` | one per slot | nothing |
| Group-held private account | either private form, keys from a group secret | every member | every member, one at a time | one per commitment | nothing |
| Shadow program's private shard | any private account, shard key `for_shadow_program(image)` | `vsk` holder | the shadow program's apply | one per commitment | nothing, and no program claim |

## Choosing

**Shared and live** (a pool, a tally, a registry, a price): public PDA. Only public state can be written by many parties in one block, and only public state can be read by settlement-time guards. Accept that its contents and every change are visible.

**Personal and hidden** (a balance, a position, a ballot, a subscription): private account or private PDA of the owner. Nobody else reads it, nobody else can interfere with it, and only the owner ever writes it, so single-writer is no constraint.

**Controlled by a program, hidden from everyone but one party** (an escrow the program releases, a vesting position, a ticket the program can burn): private PDA. The program authorizes it by seed; the party sees it; a stranger can initialize it (fund it) once.

**Controlled by a program, hidden, shared by a group** (a private treasury, a private multisig vault): group-held private PDA. Hidden from the world, visible to members, but strictly one writer per round.

**Rules that must not be visible** (a private game, a bilateral contract): a shadow program over private accounts. The chain enforces the bytecode and learns nothing, not even the program's existence, at the cost of never touching public state directly.

## Mixed placements in one program

Most real programs mix placements. A donation program has a public receipt ledger and private recipient slots. A multisig has a public proposal board and private member credentials. A stream has a public schedule and a private beneficiary account. The uniform account model is what makes this cheap: the program writes `plan.effect(&meta, ..)` the same way regardless, and the wallet decides which `meta` is public and which is private.

Two rules keep the mix sound:

1. **A guard on a public shard runs at settlement; a guard on a private shard runs in the proof.** Both fail the transaction if they do not hold, but the public one is evaluated against live state later, so it must be phrased to tolerate concurrent change (monotone, commutative).
2. **Value cannot be conjured across the boundary.** A public credit is always paired with some debit the same transaction proves (a private note's `Withdraw` or a public account's signature). The protocol enforces this per program through the ownership rule; the program enforces it across shards with two-sided bindings.

## A note on "who can read"

For public state, "everyone" includes every program: any program can be handed a public shard and inspect it. For private state, "the `vsk` holder" means only the wallet; **no program can read it either**, except in a transaction that the holder builds. The holder's wallet supplies the plaintext as a witness, and the program's apply then runs over it inside the proof. So private state is readable by the program *only when its owner chooses to run the program on it*.
