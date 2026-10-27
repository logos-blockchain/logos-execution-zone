# Automated market maker

The shipped AMM (`logos-blockchain/lez-programs: programs/amm/`) is a constant-product pool over the token program. After the incremental-updates change it settles **fixed offers** rather than quoting at execution, and that change is the clearest illustration of how a program should be shaped so that private transactions stay valid while public state moves.

## Accounts

| Account | Placement | Contents |
|---|---|---|
| Pool | public PDA, seed `H(sorted(def_a, def_b) ‖ token_program)` | `PoolDefinition { token_program_id, definitions, vault ids, lp definition id, lp supply, reserve_a, reserve_b, active }` |
| Vault A, Vault B | public PDAs, seed `H(pool ‖ definition)` | token holdings under the token program's shard, spendable only by the AMM's seed |
| LP definition | public PDA, seed `H(pool ‖ 0)` | a token definition the AMM mints and burns by seed |
| Trader / LP holdings | any: public or private token holdings | |

The pool and its vaults are public because they are shared, live state. Everything a user brings can be private.

## Swap as a fixed offer

```rust
Instruction::Swap { token_program_id, definition_id_in, definition_id_out, amount_in, amount_out }
```

The trader states exactly what they pay and exactly what they want. The plan emits one effect on the pool, `Effect::Swap(SwapBinding { .. })`, then two chained token transfers: user→input vault for `amount_in`, output vault→user for `amount_out` with the vault's seed delegated. The pool's `apply`:

```rust
assert!(binding.amount_out < reserve_out);
let quote = quote_exact_input(reserve_in, reserve_out, binding.amount_in);
assert!(binding.amount_out <= quote, "the pool cannot afford this offer at its live price");
// reserves += amount_in, -= amount_out; the difference between quote and amount_out stays in the pool
```

Because the guard is an inequality against **live** reserves, an offer prepared at 1000/1000 settles at 1100/925 if the curve still covers it, pays exactly what it asked, and is refused (not included, nothing moves) if it does not. A refused offer can be resubmitted unchanged when the price comes back. The general property, a prepared private transaction settling against public state that has since moved, is demonstrated by `two_deshielded_transfers_to_one_recipient_compose_at_settlement` in `lee/state_machine/src/state/tests/privacy_preserving.rs`: two transactions are both prepared against a recipient balance of 400, and settle against 437 and 448.

This is pattern 12 (commutative public effects) and pattern 1 (proposal and guard) together. A `Swap` that quoted at settlement (`amount_out = quote`) would need the trader's receiving effect to know the quote, which `plan` cannot; the fixed offer moves the price risk to the trader and makes the transaction state-free.

## Add and remove liquidity

Both carry the exact amounts and the exact LP delta as proposals; the pool's apply recomputes the ideal deposit and the minted or burned LP and requires equality. These are `==` guards, so a prepared add-liquidity **is** brittle: any reserve change between preparation and settlement changes the ideal ratio and the transaction is refused. That is a deliberate choice: liquidity provision is not something you want settled at a ratio you did not compute. Traders get inequalities, LPs get equalities.

{{#include ../diagrams/amm-prepared-offer.svg}}

The third column is the prepared-offer behaviour: an offer the live curve cannot afford is simply not included, the trader's note stays unspent, and the same transaction can be resubmitted when the price comes back.

## Interoperability matrix

| Trader input holding | Trader output holding | Transaction | Chain sees |
|---|---|---|---|
| Pub | Pub | public | everything |
| Priv | Priv | private; the two holdings are `Update` (input) and `Init` or `Update` (output) | pool effect with the full `SwapBinding`; vault `Deposit`/`Withdraw` with amounts; AMM and token program claims. **The trade is public, the trader is not.** |
| Priv | Pub | private | as above, plus the output holding's id |
| Pub | Priv | private, the public holding signs | as above, plus the trader's signature |

For LPs the same table applies to the three user holdings; `RemoveLiquidity` from a private LP holding publishes the amounts through the pool effect and the vault withdrawals.

## What leaks, precisely

A private swap publishes on the pool: `token_program_id, input_vault_id, output_vault_id, definition_id_in, definition_id_out, amount_in, amount_out`. It publishes on each vault: `Deposit`/`Withdraw { descriptor, amount }`. It publishes the AMM's and the token program's image claims. It publishes nothing about the trader's accounts. The trader's anonymity set is "everyone who could have made a private swap", which is everyone.

There is no way, in this design, to hide the trade itself: the pool is public state and every change to it is a public effect. The only knobs are amount granularity (round numbers reveal less than exact ones) and timing.

## Ideas

- **Limit orders are free.** A fixed offer with `plan.timestamp_window(..expiry)` is a good-till-time limit order that anyone can hold and submit when the price crosses. The AMM does not need an order book: the offers are the book, held off chain by their makers, and the sequencer's mempool is where they compete.
- **Private LP positions.** LP holdings can be private today. LP *shares* of the pool are inferable from the public LP supply and the public adds and removes, so privacy of a position is only as good as the crowd of other LPs.
- **Fee switch and rewards.** `fees` is a field the shipped pool does not use. A fee would be an extra `amount_in` fraction kept in the reserves; per-LP rewards would need the LP definition's supply and a rewards accumulator, both public.
- **Batch settlement to blunt front-running.** Offers are visible in the mempool before inclusion and a sequencer can order them. A pool that instead settles all offers in a block at one clearing price cannot be written as an LEZ program: `apply` sees one shard at a time and one effect at a time, so "the set of offers this block" is not an input. Ordering fairness is a sequencer-level property.
- **Dark pool.** Matching two private orders requires reading both, which is impossible unless one party holds both notes. A two-party swap between private accounts is possible only as an escrow with a public vault or a pairwise group key; see [Escrow, swaps, auctions](escrow-auctions.md).
- **Oracle-priced pools.** No oracle exists. A price written into a public shard by a trusted account can be inspected; the trust is the program's.
- **Private pool.** A pool held in a group-key private account is single-writer: one swap per proving round, every trader a group member. That is a private OTC desk, not an AMM.
