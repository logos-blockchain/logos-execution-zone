# Private donations

**Shows:** the mailbox · async message for strangers (9) · pseudonym (8)

## Goal

A cause publishes one address. Anyone can donate to it, from a public or a private account. Nobody can see who runs the cause, what it holds, or when it spends. Donors who give from a private account hide their gift as well.

This needs **no new program**. It is the native token and the mailbox. It comes first in the catalog because every later design uses the same move.

## Actors

| Actor | Placement | Authorized by |
|---|---|---|
| the donor's balance | public or private | the donor |
| the cause's balance | private | the cause's keys |

The cause publishes a **blinded address** of its private account and registers it once (a recovery binding, see [Private accounts](../build/private-accounts.md)).

## Messages

Only the native token's own:

- `Transfer { to, amount }`, sent by the donor to their own balance actor;
- `Credit(amount)`, sent as an async message by the donor's balance actor to the cause's address.

## How it runs

{{#include ../diagrams/donations-mailbox.svg}}

1. **Donate.** The donor sends `Transfer { to: cause_address, amount }`. Their balance actor debits and sends `Credit` as an async message. The address is not a declared public actor, so the credit is stored.
2. **Wait.** The credit sits in the mailbox. The cause does not need to be online.
3. **Collect.** The cause's wallet finds the credit, and collects it in a private transaction. Its balance grows inside a new commitment.

> **Improvement over plan/apply.** A public donor used to need a privacy-preserving transaction, with a proof, to give to a private cause, and the cause received one new account per donation. Now a public donation is a plain signed transfer, and every donation lands in the same account.

## Placements

| Donor | What an observer sees | Proofs |
|---|---|---|
| Public | the donor's account, the amount, the cause's address | none to donate, one to collect |
| Private | a sealed message; nothing else | one to donate, one to collect |

In both cases the collection is a private transaction with no readable content.

## What leaks

- **From a public donor:** who gave, how much, and to which address. The total given to that address can be summed by anyone.
- **From a private donor:** only that some private transaction sent a sealed message.
- **Never:** which account is behind the address, whether or when the credits were collected, and what the cause's balance is.

## Going further

- **One address per campaign.** The cause publishes a different blinded address for each campaign. All pay into the same account, and observers cannot link the public totals. A donor who gives **privately** needs the cause's keys and the factor to seal the gift, so that donor can tell that two campaigns are the same cause.
- **One address per donor**, for donors who want a private relationship.
- **What does not work: automatic refunds.** A stored credit cannot bounce. If a campaign fails, the cause has to send the money back itself.
