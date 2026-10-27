# Payment requests

**Shows:** accept by collecting (10)

## Goal

Bob asks Alice for money. Alice sees the request, decides, and pays with one action.

The design uses a property that looks like a hazard at first: a stored message runs with the owner's authority **only if the owner collects it with their spending key**. Collecting is consent.

## Actors

| Actor | Placement | Authorized by |
|---|---|---|
| Alice's balance | private | Alice |
| Bob's `requester` actor | public or private | Bob |

## Messages

There is no new message for the request itself. The request **is** the native token's transfer message, addressed to Alice's balance:

```rust
native_token::Message::Transfer { to: bob, amount: 10 }
```

Bob needs a program to send it for him, because an AsyncMessage comes from an actor:

```rust
/// The whole requester program: send the given bytes to the given actor, async.
fn handle_message(input: &ReceiveInput, (to, message): (Actor, Vec<u8>)) -> Response {
    assert!(input.is_authorized && input.from.is_none(), "only the owner sends requests");
    Response::keep_state().send(AsyncMessage { to, message })
}
```

## How it runs

{{#include ../diagrams/requests-accept.svg}}

1. **Request.** Bob's requester sends the `Transfer` to Alice's address as an async message. It is stored. Nothing has happened to Alice's money.
2. **Read.** Alice's wallet shows it: "pay 10 to this account, asked by this sender".
3. **Decide.**

| Alice | Effect |
|---|---|
| ignores it | nothing, forever |
| collects it without her spending key | the handler refuses: `UnauthorizedSender` |
| collects it **with** her spending key | her balance is debited and a credit is sent as an async message to Bob |

The request is consumed when collected, so it cannot be paid twice.

## Why it works

The native token's `Transfer` checks `is_authorized` and nothing else. When Alice collects with her spending key, that flag is true, and the transfer is hers.

The same fact is the model's main footgun. A wallet must never attach the spending key to a message the user has not seen. The reference wallet collects only credits, and always without the key.

> **Improvement over plan/apply.** This primitive did not exist. A request could travel as an encrypted note, but a note is only data, and the payer still had to build the payment. Here the request is the payment, waiting for consent.

## Public and private

| Requester | What an observer sees of the request |
|---|---|
| Public | who asked, the payer's address, the amount |
| Private | a sealed message |

The payment itself is a private transaction. If Bob is public, the credit to him crosses to the public side and is visible, with Alice hidden.

{{#include ../diagrams/requests-public-requester.svg}}

A **public** payer cannot be asked this way. An AsyncMessage to a public balance is delivered at once, in Bob's transaction, without the payer's signature, and fails.

## Going further

- **Limits on chain.** Put a small "mandate" actor on Alice's account that accepts bills from one sender up to a maximum, and forwards the transfer. Her wallet can then accept that sender's bills automatically.
- **Requests for anything.** The same move works for any message an owner might want to approve: a swap offer, a vote delegation, a multisig proposal.
- **What does not work: forcing payment.** Nobody can make Alice collect.
