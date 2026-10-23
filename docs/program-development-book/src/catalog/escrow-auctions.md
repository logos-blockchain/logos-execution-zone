# Escrow, swaps, auctions and flash loans

Four designs around one question: how do two or more parties who do not trust each other exchange value when each may be private? The answer is always a program-controlled vault, and the design space is which party holds the keys to see it.

## Escrow with an arbiter

### Accounts

| Account | Placement |
|---|---|
| Escrow record | any account the buyer chooses: `Escrow { terms_hash, arbiter, state, vault: AccountId, vault_seed: PdaSeed }` |
| Vault | a PDA of the program under `vault_seed`, native or token; bound to the record by content at `Fund` ([pattern 17](../patterns/index.md)) |
| Buyer, seller, arbiter | any placement; each acts when the state machine allows |

`Fund` (buyer) transfers into the vault and writes the record; `Release` (buyer, or arbiter) chains `custody_transfer` to the seller; `Refund` (seller, or arbiter) sends it back. Each instruction's plan checks `is_authorized` on the acting party's account and emits a state-transition effect on the record, whose apply enforces the allowed transitions.

Parties may be private: a private buyer funds from a private note (the vault credit is public), a private seller receives into a fresh private slot named in instruction data and pinned by a hash in the record (pattern from the [multisig](multisig.md) recipient commitment). A **private arbiter** is a secret credential: `arbiter: H(secret)`, proven from instruction data.

Chain sees: the amount (vault movements), the state transitions, and any public party's signature. Hidden: private parties' identities.

## Hash time-locked transfer

The escrow with two gates instead of an arbiter: the seller may claim with a preimage, the buyer may refund after a deadline.

```rust
enum Instruction {
    Lock  { id, hash: [u8;32], deadline_ms: u64 },
    Claim { id, preimage: [u8;32] },
    Refund{ id, now_ms: u64 },
}
enum Effect {
    Lock(Terms),                          // write_once
    ClaimWith { hash: [u8;32] },          // guard: terms.hash == hash && state == Locked; -> Claimed
    RefundAfter { now_ms: u64 },          // guard: now >= deadline && state == Locked; -> Refunded
    TimestampAtLeast(u64),                // clock guard for Refund
}
```

`Claim` computes `sha256(preimage)` in the plan and emits `ClaimWith { hash }`. In a **private** claim the preimage never appears on chain; only the hash does, which the record already held. So a private HTLC claim reveals that the lock was claimed, not by whom and not the secret. This is unlike public-chain HTLCs, where the revealed preimage is the whole point (and the leak). If the counterparty *needs* the preimage (to claim on another chain), the claimant must reveal it out of band or claim publicly.

{{#include ../diagrams/escrow-htlc-private-claim.svg}}

## Atomic swap between private accounts

Two parties, each with a private note, want to exchange. The obvious "one transaction with both witnesses" needs one wallet to hold both parties' plaintexts and nullifier keys; that is a shared wallet, not a swap. Three workable shapes:

1. **Two HTLCs on public vaults.** Each party locks into a public vault gated by the same hash; each claims privately. Amounts are public, parties hidden.
2. **Pairwise group key.** Both parties derive a shared key and create a private PDA under it for the exchange program. Party A initializes it with A's asset and terms; party B updates it (B holds the group `nsk`) depositing B's asset and taking A's, all inside the program's rules, all in one private transaction with no public footprint. The single-writer constraint is harmless with two parties acting in turn. Every detail of the trade is hidden from the chain.
3. **Bearer offer.** A prepares a private transaction whose plan gives A's asset to a fresh slot of B and takes B's asset from an account B must authorize... which B cannot do in A's proof. Rejected: authorization for B's note requires B's `ask` in B's prover. A bearer offer can only take from a **public** account of B (B signs A's prepared message) or from a program vault B funded.

{{#include ../diagrams/escrow-pairwise-swap.svg}}

## Sealed-bid auction

Commit-reveal is native to private accounts: a bid held in a bidder's private account is a commitment the bidder controls.

| Account | Placement |
|---|---|
| Auction | public PDA: `Auction { item, end_ms, reveal_end_ms, best_bid, best_bidder_tag, state }` |
| Bid | the bidder's **private PDA** of the auction program, `for_private_pda(program, H(auction_id), bidder_npk, bidder_vpk, Identifier::ZERO)`: `Bid { amount, salt }` plus the escrowed funds in its native shard |
| Bidders | private accounts |

- **Bid**: a private transaction that initializes the bid PDA with the amount and the funds (a transfer from the bidder's note). Nothing public except a clock guard (`before end_ms`). The number of bids is not even visible (seven-note padding).
- **Reveal**: a private transaction that updates the bid PDA (the program's guard reads `amount` from the private shard, in the proof) and emits a public effect `Reveal { amount, bidder_tag }` on the auction, whose apply keeps the maximum. `bidder_tag = H(secret)` lets the winner later prove they are the winner. The amount becomes public at reveal, as in every sealed-bid auction; the bidder does not.
- **Settle**: after `reveal_end_ms`, anyone submits; the winner's funds move from their bid PDA to the seller, which needs the winner's transaction (only they can update their PDA) or, better, a **program-authorized** move: the winner's bid PDA is a private PDA of the auction program, so the auction program can `custody_transfer` from it in *the winner's* reveal transaction, conditionally on winning... but winning is not known at reveal time. So settlement is a second transaction by the winner: `Claim` with a guard on the auction record (`best_bidder_tag == H(my secret)`), and the loser's `Withdraw` is symmetric. Both are private transactions with one public guard effect each.

Chain sees: reveals (amounts and tags), the winning amount, the seller's credit. Hidden: every bidder's identity, losing bids that were never revealed (a bidder may simply not reveal and withdraw later), the funding of bids.

## Flash loans

Shipped as a test program (`lee/state_machine/test_methods/guest/src/bin/flash_swap_initiator.rs`) and described in the [pattern language](../patterns/index.md) as the self-call pattern:

1. inspect the vault's balance (pin `vault_balance`);
2. `custody_transfer` out;
3. chain the borrower's callback with the vault and receiver accounts;
4. chain **yourself** with `InvariantCheck { min_vault_balance }`, which asserts `caller == self` and inspects the vault again.

If the callback does not return the funds, step 4 panics and the whole transaction, including step 2, is void. Flash loans are inherently public: the vault is public, the amounts are public. A private borrower can run the whole thing as a private transaction (the callback's private effects stay hidden), but every vault movement is a public effect.

## Interoperability matrix (escrow family)

| Design | Parties | Vault | Hidden | Visible |
|---|---|---|---|---|
| Arbiter escrow | any | public | private parties' identities | amount, states, arbiter tag |
| HTLC | any | public | claimant identity, preimage (if claimed privately) | amount, hash, deadline |
| Pairwise group PDA | both private | private (group) | everything | nothing |
| Sealed-bid auction | private bidders | per-bidder private PDAs | bidders, unrevealed bids | revealed amounts, winner tag |
| Flash loan | any | public | the borrower's private logic | every vault movement |

## Ideas

- **Escrow with private amount**: put the vault in a pairwise group PDA and the record with it. Only the two parties (and the program, in their proofs) know the amount. Add a private arbiter by sealing the group key to a third party.
- **Dutch auction**: price decreases with the clock; `Buy { now_ms, price }` with a clock guard `>=` and a record guard `price == price_at(now)`. The `==` on price makes prepared buys brittle; propose the time and let the apply compute the price from it instead, with `price_paid >= price_at(now)` and the surplus kept, which is the AMM's fixed-offer trick again.
- **Vickrey (second-price)**: same reveal machinery; the apply tracks the top two amounts.
- **What does not work:** private atomic swaps with no shared key and no public vault; auctions whose bids are hidden *after* the auction ends (a bid must be revealed to compete; unrevealed bids simply lose); any escrow where the program must "take" from a private account without its owner's transaction.
