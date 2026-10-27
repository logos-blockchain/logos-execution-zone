# Payment streams

**Shows:** anyone may poke (11) · seed-authorized custody (13) · clock assertion (17) · async message for strangers (9)

## Goal

A salary paid by the second. The recipient can be private and offline. Nobody runs a server for the payer.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(stream, streams)` | recipient, rate, start time, amount released so far | public PDA |
| `(stream, native)` | the money not yet released | same account |

The stream is public on purpose. It must be something **anyone** can move forward, and only a public actor has that property.

## Messages

```rust
enum Message {
    /// Once, by whoever funds the stream.
    Open { recipient: AccountId, rate_per_ms: u128, start: Timestamp, seed: PdaSeed },
    /// By anyone, at any time.
    Release { now: Timestamp },
}
```

## Handler

```rust
Message::Release { now } => {
    let mut stream = Stream::from_bytes(&input.pre_state);
    let due = (now - stream.start) as u128 * stream.rate_per_ms - stream.released;
    stream.released += due;

    Response::set_state(stream.to_bytes())
        // The claim about time is checked by the clock, or the transaction fails.
        .send_sync(clock(), &clock_core::Message::AssertTimestamp { at_least: now, at_most: Timestamp::MAX })
        // Pay from the stream's own balance. The credit is an AsyncMessage.
        .send(native_token::custody_transfer(
            input.receiver.account_id, stream.seed, stream.recipient, due))
}
```

`Open` writes the stream's settings once (`write_once`). It must also check that the seed is its own: `AccountId::for_public_pda(&program, &seed) == input.receiver.account_id`. If a wrong seed were stored, every later payout would fail and the funds would be stuck. Funding is a plain transfer to the stream's account.

## What to notice

**The handler cannot read the time.** The caller states `now` and the clock confirms it. Stating an earlier time releases less. Stating a later time fails.

**`Release` needs no authorization.** The recipient sends it when they want their money. So can anyone else. The handler only ever does what the schedule allows, so it does not matter who asks.

**No key can touch the funds.** They sit on a PDA, and only this handler grants the seed.

**The payout is an AsyncMessage**, so the recipient's kind does not matter.

> **Improvement over plan/apply.** In the earlier book's stream a private recipient withdrew for themselves: a privacy-preserving transaction with a proof, paying into a new account each time. Now anyone can release with a plain public transaction, and the recipient collects into one account.

## How it runs with a private recipient

{{#include ../diagrams/streams-private-recipient.svg}}

With a public recipient there is no third step:

{{#include ../diagrams/streams-all-public.svg}}

1. The payer opens and funds the stream, naming the recipient's **address**.
2. Someone pokes `Release`. The credit is stored on chain.
3. The recipient collects when convenient.

## Public and private

| Payer | Recipient | What an observer sees |
|---|---|---|
| Public | Public | everything |
| Public | Private | payer, rate, amounts, destination address |
| Private | Private | rate and amounts; neither party |

A private payer funds the stream under a blinded address. The schedule is public in every case, because the stream is. Privacy here is about **who**, not **how much**.

## Going further

- **Vesting.** Add a cliff: release nothing before it.
- **Inheritance.** A vault that pays an heir's address once its owner has sent no `Heartbeat` for a year. Same three patterns.
- **What does not work: streaming out of a private account by poke.** Only its owner can run a private handler. For per-payment privacy, see [Payment channels](channels.md).
