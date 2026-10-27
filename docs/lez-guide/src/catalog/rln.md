# Rate-limiting nullifiers

**Shows:** the seat (4) · the proof-carrying message (7) · pseudonym (8) · clock assertion (17)

## Goal

A rate-limiting nullifier (RLN) lets a network accept anonymous messages and still limit how many each member sends. Logos uses it to protect its mix network from spam.

It has two halves, and only one of them is a program.

- **On chain: a membership registry.** A member pays a fee and registers a commitment to a secret. The registry keeps the commitments in a Merkle tree and publishes the root.
- **Off chain: the rate limit.** Every message carries a zero-knowledge proof that its sender is in the tree, plus a small piece of the sender's secret. A sender who stays within their limit reveals nothing. A sender who exceeds it reveals the whole secret, and anyone who learns the secret can have the member removed.

This entry is a toy version of the registry. The real one is the Logos program in the repository `logos-co/logos-lez-rln`. It is written for the earlier plan/apply model, so what follows is that design moved to actors and cut down.

## Off chain, in brief

A member holds a secret `a0`. Their commitment is `H(a0)`. They registered with a `rate_limit`: the number of messages they may send per epoch.

For each message they pick a slot number below their limit and compute:

```text
a1 = H(a0, epoch, slot)      // a different line for each slot of each epoch
x  = H(message)
y  = a0 + a1 · x             // one point on that line
nullifier = H(a1)            // the same for every message that uses this slot
```

The proof shows that the sender's leaf is under the on-chain root, that `slot` is below the registered limit, and that the point and the nullifier were computed honestly. It does not show which member.

Sending more than `rate_limit` messages in an epoch forces a slot to be used twice. Two messages in one slot give two points on one line, and two points give `a0`. The network notices because the two messages carry the same nullifier.

None of this touches the chain. Peers verify the proofs against the root they read from the registry. The arithmetic follows the RLN v2 design as this book understands it. The proving code lives in other Logos repositories that this book has not examined.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(registry, rln)` | price, treasury, the members and their limits, the Merkle root | public PDA |
| `(payer, rln)`: a seat | nothing | on the payer's account, public or private |

The registry stores `commitment → rate_limit` for each member. A leaf of the tree is `H(commitment, rate_limit)`, so the off-chain proof can use the limit.

## Messages

```rust
enum Message {
    /// To a seat, by its owner.
    Register { registry: Actor, id_commitment: [u8; 32], rate_limit: u64,
               fee: u128, treasury: AccountId },
    /// From a seat to the registry: "I paid `fee` to `treasury` for this member."
    Enroll { id_commitment: [u8; 32], rate_limit: u64, fee: u128, treasury: AccountId },
    /// To the registry, by anyone who knows a member's secret.
    Slash { identity_secret: [u8; 32] },
}
```

## Handler

```rust
fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    match message {
        // The seat: check the owner, pay the fee, tell the registry.
        Message::Register { registry, id_commitment, rate_limit, fee, treasury } => {
            assert!(input.is_authorized && input.from.is_none(), "only the owner registers");
            Response::keep_state()
                .send_sync(Actor::native_balance(input.receiver.account_id),
                      &native_token::Message::Transfer { to: treasury, amount: fee })
                .send_sync(registry, &Message::Enroll { id_commitment, rate_limit, fee, treasury })
        }

        // The registry: a seat of this program says it paid. Check the price, add the member.
        Message::Enroll { id_commitment, rate_limit, fee, treasury } => {
            assert!(input.from_own_program(), "only a seat enrolls");
            let mut reg = Registry::from_bytes(&input.pre_state);
            assert!((MIN_RATE..=MAX_RATE).contains(&rate_limit));
            assert_eq!(treasury, reg.treasury, "paid the wrong account");
            assert_eq!(fee, reg.price_per_unit * rate_limit as u128, "paid the wrong amount");
            assert!(reg.members.insert(id_commitment, rate_limit).is_none(), "already a member");
            reg.root = merkle_root(&reg.members);
            Response::set_state(reg.to_bytes())
        }

        // The registry: whoever knows the secret may remove the member.
        Message::Slash { identity_secret } => {
            let mut reg = Registry::from_bytes(&input.pre_state);
            reg.members.remove(&hash1(&identity_secret)).expect("not a member");
            reg.root = merkle_root(&reg.members);
            Response::set_state(reg.to_bytes())
        }
    }
}
```

## How it runs

{{#include ../diagrams/rln-lifecycle.svg}}

1. **Register.** The member tells their seat to register. The seat pays the fee from the account it sits on and tells the registry. Both SyncMessages are in one transaction: if the registry refuses, the payment is undone.
2. **Send messages.** Off chain, with proofs against the registry's root.
3. **Overspend.** Two messages in one slot expose the secret.
4. **Slash.** Anyone sends the secret to the registry. The member is gone, and the root changes.

## What to notice

**The registry never sees the money move, and does not need to.** It cannot read the treasury's balance. It trusts the message `Enroll { fee, treasury }` because the message comes from a seat of its own program, and the only code in this program that sends `Enroll` has just sent that transfer. The registry only checks that the amount and the destination are the right ones.

**Slashing needs no evidence, only the secret.** The registry does not see the two offending messages. Only a member who overspent leaks their secret.

**The fee is the deterrent.** The Logos program charges `price_per_unit × rate_limit` to a treasury and pays nothing back. A slashed member loses a paid membership. There is no stake and no reward for the slasher.

> **Improvement over plan/apply.** The Logos program's `Register` carries the price, two durations and a program id as "claims": values the caller restates because `plan` cannot read them, each checked later against the stored one. Its header says so: "every stored value an instruction depends on travels in it as a claim". A handler reads its own state, so `Slash` here takes one argument where the original takes six. The two claims left in `Register` exist for a different reason: the seat pays before the registry speaks.

## What private actors bring

**One thing, and it matters: the registration can be anonymous.**

RLN hides which member sent a message. It does not hide who the members are. When the seat is on a public account, the registration is a signed transaction: everyone sees that this account paid for this commitment. Two consequences follow.

- The membership list is a list of accounts that use the network.
- When a member is slashed, the published secret gives the commitment, and the commitment gives the account that paid for it.

Put the seat on a **private** account and both links disappear.

{{#include ../diagrams/rln-private-registration.svg}}

- The seat runs inside the member's proof. Its payment and its `Enroll` cross to the public side from a blinded address.
- The registry accepts it for the same reason as before: it comes from a seat of its own program. Here that fact is proven, not observed.
- The chain sees a commitment enter the tree and the treasury receive a fee. It does not see who paid.

| Seat | Chain sees at registration | A slash reveals |
|---|---|---|
| Public | payer, commitment, rate limit, fee | the commitment, and so the payer |
| Private | commitment, rate limit, fee | the commitment only |

The handler has no code for this. It is the same three arms, and the member chooses by which account they use. On other chains this takes a mixer or a relayer in front of the registry.

**What private actors do not bring.**

- **A private registry.** The members and the root must be public, because every peer verifies proofs against the root.
- **The rate limit itself.** That is the off-chain proof. No actor takes part in it.
- **A hidden rate limit.** The limit is in the leaf and in the fee.

**A caution.** A commitment registered a minute before a burst of messages is easy to connect to that burst. Register early.

## Going further

- **Expiry and renewal.** The Logos program gives each membership an active period and a grace period, lets the member renew by paying again, and lets anyone erase an expired one. Each needs the time: a clock assertion with some slack, since a claim that must equal the clock exactly fails whenever the clock moves.
- **A real tree.** The toy recomputes the root from the member list. The Logos program keeps a fixed-depth incremental Poseidon tree and updates one path per change.
- **A cap.** The Logos program limits the sum of all rate limits.
- **A reward for slashing.** Keep fees on a PDA and send part as an async message to an address the slasher names. A private slasher stays unknown.
- **A private counter is not RLN.** A counter in a private actor's state limits actions that go through the chain (see [Credentials](credentials.md)). It cannot limit messages that never touch the chain, which is what RLN is for.
