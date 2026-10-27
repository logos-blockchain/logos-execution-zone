# Escrow and sealed bids

**Shows:** the public referee (12) · seed-authorized custody (13) · the proof-carrying message (7) · windows for expiry (16)

Two different people's private accounts cannot act in one transaction (see [limits](../privacy/limits.md)). So when two private parties exchange value, a public actor stands between them, holds the value from one transaction to the next, and has a deadline.

## Part 1: escrow

### Goal

Alice pays Bob for a delivery. Bob is paid when Alice confirms. If she never does, an arbiter decides. Any of the three can be private.

### Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(deal, escrow)` | the addresses of buyer, seller and arbiter | public PDA |
| `(deal, native)` | the payment | same account |

### Messages

```rust
enum Message {
    /// Once, by the buyer, who then funds the deal's account.
    Open { buyer: AccountId, seller: AccountId, arbiter: AccountId, amount: u128, seed: PdaSeed },
    /// A party tells their own seat what they want. The seat tells the deal.
    Release { deal: AccountId },
    Refund { deal: AccountId },
}
```

### Handler

The program plays two roles, told apart by the sender.

```rust
fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let program = input.receiver.program_account_id;
    match (input.from, message) {
        // Role 1, a party's seat: check the owner, pass the message on.
        (None, Message::Release { deal } | Message::Refund { deal }) => {
            assert!(input.is_authorized, "only the owner uses this seat");
            Response::keep_state().send_sync(Actor::new(deal, program), &message)
        }

        // Role 2, the deal: a seat of this program is speaking.
        (Some(seat), message) => {
            assert!(input.from_own_program(), "only seats speak to a deal");
            let deal = Deal::from_bytes(&input.pre_state);
            let who = seat.account_id;
            let to = match message {
                Message::Release { .. } if who == deal.buyer || who == deal.arbiter => deal.seller,
                Message::Refund { .. } if who == deal.seller || who == deal.arbiter => deal.buyer,
                _ => panic!("not yours to decide"),
            };
            Response::keep_state().send(native_token::custody_transfer(
                input.receiver.account_id, deal.seed, to, deal.amount))
        }

        (None, Message::Open { .. }) => /* write the settings once; check the seed derives this account */,
    }
}
```

### What to notice

**The deal identifies a party by a seat of its own program, never by an account id alone.** Anyone can deliver a message to any program's actor on any public account. So "the sender's account is the buyer's" proves nothing unless the sending **program** is one that checked the owner's authorization. The seat does that check, and `from_own_program()` proves the sender was a seat.

**A private party stays hidden.** Their seat presents a blinded address, and that address is what `Open` recorded.

**Payouts are AsyncMessages** to those same addresses.

**The arbiter is just another address.** It can be a person, or a [multisig](multisig.md) with hidden members.

### How it runs

{{#include ../diagrams/escrow-all-public.svg}}

{{#include ../diagrams/escrow-private-parties.svg}}

### What leaks

The amount, the timing, and which of the three addresses ended the deal. Not who is behind any of them.

## Part 2: a sealed-bid auction

### Goal

Bidders submit bids nobody can see. After the deadline every bid is revealed and the highest wins. A bid cannot be changed after it is placed.

### Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(auction, auctions)` | the deadline, and the revealed bids by pseudonym | public PDA |
| `(bidder, auctions)`: a paddle | the bidder's secret amount | private, on each bidder's account |

### How it runs

{{#include ../diagrams/auction-sealed-bid.svg}}

1. **Bid.** The bidder tells their paddle an amount. The paddle stores it, once, and sends the auction `Joined` under a blinded address.
2. **Reveal.** After the deadline, the bidder tells the paddle to reveal. The paddle sends `Reveal { amount }` with the amount it stored.
3. **Settle.** Anyone pokes the auction. The highest revealed amount wins.

### The paddle's handler

```rust
Message::Bid { auction, amount } => {
    assert!(input.is_authorized && input.from.is_none());
    Response::set_state(write_once(&input.pre_state, encode(&(auction, amount))))
        .send_sync(auction_actor(auction), &Internal::Joined)
}
Message::RevealBid => {
    assert!(input.is_authorized && input.from.is_none());
    let (auction, amount) = decode(&input.pre_state);
    Response::keep_state().send_sync(auction_actor(auction), &Internal::Reveal { amount })
}
```

The auction accepts `Joined` before the deadline and `Reveal` after it, both only from its own program.

### What to notice

**There is no commitment to open.** In the classic design a bidder publishes a hash and later reveals the amount and a salt, and the contract re-hashes. Here the bid sits in the paddle's private state, written once. The reveal is the paddle's own code reading that state inside a proof. The auction trusts the amount because of **who sent it**.

**A bidder who never reveals** is simply not counted. That leaves a loophole: one person can run several paddles from several private accounts, place a different bid with each, and reveal only the one that suits them. A paddle cannot change its bid, but a person can choose among paddles. Closing it takes a deposit at `Joined`, forfeited without a reveal, and large enough to outweigh the gain.

### What leaks

How many bids there are and when each arrived. After the deadline, every revealed amount, under a pseudonym. Never who the bidders are.

## Going further

- **Deadlines without a clock message.** `Release` after a timeout: return a validity window from the handler (pattern 16).
- **Swaps.** An escrow that holds both sides' deposits and pays each to the other when the second arrives.
- **What does not work: a private order book.** Matching needs someone to see both sides.
