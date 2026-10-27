# Payment channels

**Shows:** seed-authorized custody (13) · pseudonym (8) · async message for strangers (9) · anyone may poke (11)

## Goal

Many small payments between two parties with **one** transaction to start and one to finish, in the style of Bitcoin's Lightning. The payments in between are signed messages exchanged off chain. They are instant, free, and invisible to everyone else.

This is the smallest version: a one-way channel from a payer to a recipient.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(channel, channels)` | the payer's voucher key, the recipient's address, the amount paid out so far, an expiry | public PDA |
| `(channel, native)` | the channel's funds | same account |

## Messages

```rust
enum Message {
    /// Once, by the payer.
    Open { voucher_key: VerifyingKey, recipient: AccountId, refund_to: AccountId,
           capacity: u128, expiry: Timestamp, seed: PdaSeed },
    /// By anyone holding a voucher.
    Redeem { total: u128, signature: Signature },
    /// By anyone, after the expiry.
    Close,
}
```

## Off chain

A **voucher** is the payer's signature over `(channel, total)`: "this channel owes the recipient `total` so far".

To pay 1 more, the payer signs a voucher with `total + 1` and sends it to the recipient directly. Nothing touches the chain. The recipient keeps only the latest voucher, since it is worth more than all earlier ones.

## Handler

```rust
Message::Redeem { total, signature } => {
    let mut channel = Channel::from_bytes(&input.pre_state);
    let voucher = borsh::to_vec(&(input.receiver.account_id, total)).unwrap();
    channel.voucher_key.verify_strict(&voucher, &signature).expect("bad voucher");

    let due = total.checked_sub(channel.paid).expect("an older voucher");
    channel.paid = total;
    Response::set_state(channel.to_bytes())
        .send(native_token::custody_transfer(
            input.receiver.account_id, channel.seed, channel.recipient, due))
}

Message::Close => {
    let channel = Channel::from_bytes(&input.pre_state);
    let rest = channel.capacity - channel.paid;
    Response::keep_state()
        .timestamp_window(channel.expiry..)          // only valid after the expiry
        .send(native_token::custody_transfer(
            input.receiver.account_id, channel.seed, channel.refund_to, rest))
}
```

`Open` writes the settings once. It must also check that the seed is its own: `AccountId::for_public_pda(&program, &seed) == input.receiver.account_id`. If a wrong seed were stored, every later payout would fail and the funds would be stuck.

Funding is a plain transfer of `capacity` to the channel's account. The handler cannot read its own balance (it is another actor), so the recipient checks off chain that the account really holds `capacity` before accepting vouchers.

Checking a signature inside a handler is ordinary code. The stake program already does it for its approvals (`lez/programs/sequencer_stake/src/main.rs`).

## What to notice

**Neither side can cheat.** The recipient can only redeem what the payer signed. The payer cannot take money back before the expiry, because no key controls the PDA. The recipient redeems before the expiry, and the payer gets the rest after it.

**`Redeem` needs no authorization.** A voucher is the authorization. Whoever submits it, the money goes to the recipient's address.

**The voucher key is not an account key.** It is made for this one channel, so it links to nothing.

> **Improvement over plan/apply.** Settling to a private recipient and refunding a private payer no longer need that party to act. Anyone can redeem or close, and the money waits for its owner.

> **Trade-off.** Under plan/apply the channel funded itself inside `Open`, so its capacity was real by construction. Here the balance is a different actor, and the recipient checks it off chain.

## How it runs

With a public payer and a public recipient, everything is visible and the payout lands at once:

{{#include ../diagrams/channels-all-public.svg}}

With both private, the payer is hidden and the payouts wait to be collected:

{{#include ../diagrams/channels-one-way.svg}}

## Public and private

Both parties can be private. The recipient and the refund are addresses, and payouts are AsyncMessages.

### Funding from a private account

1. **Open.** Someone writes the channel's settings. `Open` needs no authorization and writes once, so the recipient can send it, using the voucher key and refund address the payer gave them.
2. **Check.** The payer reads the public record and confirms every setting: voucher key, recipient, refund address, capacity, expiry. Write-once means it cannot change afterwards.
3. **Fund.** The payer sends one private transaction: `Transfer { to: channel, amount: capacity }` to their own private balance. The debit happens in the proof. The credit crosses to the channel's public balance.

The payer never sends a public transaction. Observers see the channel receive its capacity from a private balance, shown at whatever address the payer's wallet presented. A blinded address there reveals nothing.

The order matters. A payer who funds before checking can be robbed by whoever wrote the settings first.

The refund address is a blinded address of the payer, registered beforehand. `Close` sends the remainder to it as an async message, and the payer collects privately.

| An observer sees | |
|---|---|
| that a channel exists, and its capacity | yes |
| the total redeemed, and when | yes |
| how many payments there were, and their sizes | no |
| who the payer is | no |
| who the recipient is | no |

Compare with a [payment stream](streams.md): a stream publishes every release. A channel publishes only the final sum.

## Going further

- **Two-way channels.** Both parties sign each new pair of balances, with a counter. Closing starts a waiting period (a clock assertion) during which the other side can present a newer signed state.
- **A fully hidden channel.** Put the channel on a private PDA owned by the two parties as a group (pattern 18). Either can operate it, the program still enforces the signatures, and even the capacity is hidden. The price is a race: every update to a private account replaces its commitment, so a payer who keeps touching the account can make the recipient's pending redemption stale, again and again, until the expiry. A public channel has no such race.
- **Routed payments.** Lightning routes a payment across several channels with hashlocks. A channel here can hold a hashlocked amount the same way. The routing network is off-chain software that this book has not designed.
- **What does not work: a voucher worth more than the channel.** A voucher is only as good as the funds behind it. The recipient checks the capacity and the expiry before accepting, and redeems before the expiry.
