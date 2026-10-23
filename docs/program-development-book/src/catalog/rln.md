# Rate-limiting nullifiers

## Background

A rate-limiting nullifier (RLN) lets a network accept anonymous messages and still limit how many each member sends. Logos uses it to protect its mix network from spam.

It has two halves, and only one of them is a program.

- **On chain: a membership registry.** A member pays a fee and registers a commitment to a secret. The registry keeps all commitments in a Merkle tree and publishes the root.
- **Off chain: the rate limit.** Every message carries a zero-knowledge proof that its sender is in the tree, plus a small piece of the sender's secret. A sender who stays within their limit reveals nothing. A sender who exceeds it reveals the whole secret, and anyone who learns the secret can have the member removed.

This chapter is a toy version of the registry, following the Logos program in the repository `logos-co/logos-lez-rln`, which is written for this same plan/apply model. That program is the real thing: it keeps an incremental Poseidon tree in a second program, snapshots durations into each membership, and handles renewal. The toy keeps the shape and drops the rest.

## Off chain, in brief

A member holds a secret `a0`. Their commitment is `H(a0)`. They registered with a `rate_limit`: the number of messages they may send per epoch.

For each message they pick a slot number below their limit and compute:

```text
a1 = H(a0, epoch, slot)      // a different line for each slot of each epoch
x  = H(message)
y  = a0 + a1 · x             // one point on that line
nullifier = H(a1)            // the same for every message that uses this slot
```

The proof shows that the sender's leaf is under the on-chain root, that `slot` is below the registered limit, and that `(x, y)` and the nullifier were computed honestly. It does not show which member.

Sending more than `rate_limit` messages in an epoch forces a slot to be used twice. Two messages in one slot give two points on one line, and two points give `a0`. The network notices because the two messages carry the same nullifier.

None of this touches the chain. Peers verify the proofs against the root they read from the registry. The arithmetic follows the RLN v2 design as this book understands it. The proving code lives in other Logos repositories that this book has not examined.

## Accounts

| Account | Placement | Contents |
|---|---|---|
| Config | public PDA of the program | `Config { price_per_unit, treasury, total_rate_limit, max_total_rate_limit, active_ms }` |
| Tree | public PDA of the program | the leaves and their Merkle root |
| Membership, one per commitment | public PDA, seed derived from the commitment | `Membership { rate_limit, expires_ms }` |
| Treasury | an ordinary public account | receives the fees |
| Payer | public or private | pays the fee |
| Clock | `CLOCK_50_PROGRAM_ACCOUNT_ID` | read-only |

All three program accounts are public by design, so deriving their addresses in `plan` is right (pattern 17 makes that exception). The membership PDA is what refuses a second registration of the same commitment.

A leaf is `H(commitment, rate_limit)`. The limit is part of the leaf so that the off-chain proof can use it.

## Instructions and effects

```rust
enum Instruction {
    Register { id_commitment: [u8; 32], rate_limit: u64,
               now_ms: u64, price_per_unit: u128 },          // the last two are claims
    Slash    { identity_secret: [u8; 32], rate_limit: u64 }, // by anyone
}
enum Effect {
    // config
    Admit   { price_per_unit: u128, treasury: AccountId, rate_limit: u64 }, // guard, then count
    Release { rate_limit: u64 },                                            // uncount
    // membership
    Enrol(Membership),                                    // write once
    Expel { rate_limit: u64 },                            // guard, then clear
    // tree
    Insert([u8; 32]),
    Remove([u8; 32]),
    // clock (another program's shard)
    ClockIs(u64),
}
```

`plan` cannot read the config, so the price travels in the instruction as a **claim** and the config's `apply` checks it. The Logos program says the same in its own header: "every stored value an instruction depends on travels in it as a claim".

## A simple version

```rust
fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Register { id_commitment, rate_limit, now_ms, price_per_unit } => {
            let [config, tree, membership, payer, treasury, clock] =
                <&[_; 6]>::try_from(input.accounts.as_slice()).unwrap();
            assert!(payer.is_authorized, "the payer must authorize the fee");
            assert!((MIN_RATE..=MAX_RATE).contains(&rate_limit));
            require_pda(input, membership, &member_seed(&id_commitment));   // one per commitment
            // (config, tree and clock are pinned to their addresses the same way)

            plan.effect(config, &Effect::Admit {
                price_per_unit, treasury: treasury.account_id, rate_limit });
            plan.inspect(clock, clock.program_account_id, &Effect::ClockIs(now_ms));
            plan.effect(membership, &Effect::Enrol(Membership {
                rate_limit, expires_ms: now_ms + ACTIVE_MS }));
            plan.effect(tree, &Effect::Insert(hash2(&id_commitment, &rate_limit)));
            plan.call(ChainedCall::new(NATIVE_TOKEN_PROGRAM_ID,
                vec![ProgramShardSelector::from(payer), ProgramShardSelector::from(treasury)],
                &native_token::Instruction::Transfer { amount: price_per_unit * rate_limit as u128 }));
        }
        Instruction::Slash { identity_secret, rate_limit } => {
            let [config, tree, membership] = <&[_; 3]>::try_from(input.accounts.as_slice()).unwrap();
            let id_commitment = hash1(&identity_secret);          // knowing the secret is the proof
            require_pda(input, membership, &member_seed(&id_commitment));

            plan.effect(membership, &Effect::Expel { rate_limit });
            plan.effect(config, &Effect::Release { rate_limit });
            plan.effect(tree, &Effect::Remove(hash2(&id_commitment, &rate_limit)));
        }
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Admit { price_per_unit, treasury, rate_limit } => {
            let mut c = Config::from_bytes(pre_data);
            assert_eq!((c.price_per_unit, c.treasury), (price_per_unit, treasury), "stale claim");
            c.total_rate_limit += rate_limit;
            assert!(c.total_rate_limit <= c.max_total_rate_limit, "the registry is full");
            Some(c.to_bytes())
        }
        Effect::Enrol(m) => Some(write_once(pre_data, m.to_bytes())),
        Effect::Expel { rate_limit } => {
            assert_eq!(Membership::from_bytes(pre_data).rate_limit, rate_limit, "wrong claim");
            Some(Vec::new())
        }
        Effect::ClockIs(now_ms) => {
            let t = ClockAccountData::from_bytes(pre_data).timestamp;
            assert!(now_ms <= t && t - now_ms <= TOLERANCE_MS, "stale clock claim");
            None
        }
        /* Release, Insert, Remove: one shard each */
    }
}
```

{{#include ../diagrams/rln-lifecycle.svg}}

## What to notice

**Slashing needs no evidence, only the secret.** The program does not see the two offending messages. Whoever can present `identity_secret` whose hash is a registered commitment may remove it. Only a member who overspent leaks that secret.

**The fee is the deterrent.** The Logos program charges `price_per_unit × rate_limit` to a treasury and pays nothing back. A slashed member loses a paid membership. There is no stake and no reward for the slasher.

**The clock claim has slack.** `now_ms` may be a little behind the clock, never ahead. An exact match would fail every transaction that straddles a clock update.

**Claims everywhere.** `price_per_unit` and `rate_limit` are restated by the caller wherever `plan` needs a stored value. A wrong claim fails the transaction in the `apply` of the shard that knows the truth.

## What private accounts bring

**One thing, and it matters: the registration can be anonymous.**

RLN hides which member sent a message. It does not hide who the members are. With a public payer, the registration is a signed transaction: everyone sees that this account paid for this commitment. Two consequences follow.

- The membership list is a list of accounts that use the network.
- When a member is slashed, the published secret gives the commitment, and the commitment gives the account that paid for it.

Pay from a **private** account and both links disappear. `Register` only requires that the payer is authorized and chains a native transfer from it. In a privacy-preserving transaction the debit happens inside the proof, and the chain sees a commitment enter the tree and the treasury receive a fee. This follows from the model. This book did not check whether the Logos repository exercises it.

{{#include ../diagrams/rln-private-registration.svg}}

| Payer | Chain sees at registration | A slash reveals |
|---|---|---|
| Pub | payer, commitment, rate limit, fee | the commitment, and so the payer |
| Priv | commitment, rate limit, fee | the commitment only |

On other chains this takes a mixer or a relayer in front of the registry. Here it is the same instruction with a different account.

**What private accounts do not bring.**

- **A private registry.** The tree and its root must be public, because every peer verifies proofs against the root.
- **The rate limit itself.** That is the off-chain proof. No account, public or private, takes part in it.
- **A hidden rate limit.** The limit is in the leaf and in the fee.

**A caution.** A commitment that is registered a minute before a burst of messages is easy to connect to that burst. Register early.

## Limits

- The registry is public, so the number of members and each member's limit are public.
- Slashing needs someone to notice the double use off chain and send the transaction.
- The toy stores an expiry and does nothing with it. The Logos program adds a grace period, renewal by paying again, and erasure of expired memberships by anyone.
- The toy keeps the leaves in one shard. The Logos program keeps a fixed-depth tree in a second program and updates it by chained call.

## Variations and ideas

- **Rate limiting on chain.** An earlier version of this chapter ran the whole scheme as a program: each action was a private transaction that wrote its share into a public "share log" account whose address was the nullifier, so a second use in one slot collided. It suits actions that are themselves transactions (a faucet, a public inbox). It is not how Logos uses RLN.
- **A private counter.** For an action the member performs in their own private transaction, a counter in their own private account is enough: the program refuses to count past the limit, inside the proof. No tree, no shares, no slashing. It limits on-chain actions only.
- **A reward for slashing.** Hold fees in a vault PDA and pay part to the slasher, into a fresh private slot if they want to stay unknown.
