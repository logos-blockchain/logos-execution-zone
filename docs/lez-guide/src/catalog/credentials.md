# Credentials and tickets

**Shows:** the proof-carrying message (7) · pseudonym (8)

## Goal

An issuer gives a person a badge. The person later shows a venue that they hold one. The venue learns that the badge is real, and nothing about who is showing it.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(issuer, badges)` | nothing; it only issues | public |
| `(holder, badges)`: a badge | which issuer gave it | private, on the holder's account |
| a venue | its own business | public, any program |

## Messages

```rust
enum Message {
    /// To the issuer's actor, by the issuer.
    Issue { to: AccountId },
    /// Between badge actors: "you now hold a badge from me".
    Badge,
    /// To a badge, by its holder.
    Show { venue: Actor },
}

/// What the venue receives.
struct Attested { issuer: AccountId }
```

## Handler

```rust
fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let me = input.receiver;
    match message {
        Message::Issue { to } => {
            assert!(input.is_authorized && input.from.is_none(), "only the issuer issues");
            Response::keep_state().send_async(Actor::new(to, me.program_account_id), &Message::Badge)
        }
        Message::Badge => {
            let issuer = input.from.filter(|_| input.from_own_program()).expect("not a badge");
            Response::set_state(write_once(&input.pre_state, issuer.account_id.to_bytes()))
        }
        Message::Show { venue } => {
            assert!(input.is_authorized && input.from.is_none(), "only the holder shows");
            let issuer = AccountId::from_bytes(&input.pre_state).expect("no badge here");
            Response::keep_state().send_sync(venue, &Attested { issuer })
        }
    }
}
```

The venue's side is one check:

```rust
let badge = input.from.expect("an attestation has a sender");
assert_eq!(badge.program_account_id, BADGES_PROGRAM, "not from a badge");
```

## How it runs

{{#include ../diagrams/credentials-show.svg}}

1. **Issue.** The issuer's actor sends `Badge` to the holder's address as an async message.
2. **Collect.** The holder's badge actor stores the issuer. It accepts `Badge` only from the badges program.
3. **Show.** The holder sends `Show` in a private transaction. The badge sends a SyncMessage to the venue under a fresh blinded address.
4. **Admit.** The venue sees a message from the badges program naming an issuer it trusts.

## Why the venue can believe it

The only code that sends `Attested` is the `Show` arm, and it sends the issuer it read from its own state. That state can only have been written by the `Badge` arm, which only accepts the badges program as sender. The whole chain ran inside proofs.

The venue checked no signature and no membership proof. It checked which **program** spoke.

> **Improvement over plan/apply.** A venue's program used to inspect the credential's data itself, with a guard, so it had to understand every credential format it accepted. Now the badge program does the checking and the venue only checks who is speaking. Any program can accept badges without knowing how they are stored.

## Public and private

| Holder | What the venue learns |
|---|---|
| Private | "a badge from this issuer", from a one-time address |
| Public | the same, and who you are |

{{#include ../diagrams/credentials-public-holder.svg}}

## What leaks

- **At issue time:** that the issuer gave a badge to an address.
- **At show time:** the venue, the issuer, the time.
- **Never:** which badge it was, or any link between two visits.

## Going further

- **Tickets.** Add a `used` flag to the badge state and set it in `Show`. The badge then works once.
- **Rate limits.** Keep a counter per day in the badge state and refuse `Show` past the limit. Because every run starts from the account's real latest state, the limit cannot be exceeded, however the holder arranges their transactions. This limits actions that go through the chain. For messages that never touch it, see [Rate-limiting nullifiers](rln.md).
- **Attributes.** Store a birth date in the badge and have `Show` send only `AgeAtLeast(18)`. The handler computes the answer inside the proof and sends only the answer.
- **What does not work: asking about someone else.** A venue cannot query whether a person holds a badge. Only the holder can show it.
