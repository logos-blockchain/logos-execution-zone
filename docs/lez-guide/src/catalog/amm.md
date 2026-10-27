# Automated market maker

A constant-product pool over a token program. This entry is different from the rest of the catalog in one way that has to be stated before the design: the AMM is a real deployed program, and it is not written against the model this guide documents.

## Where it is

`logos-blockchain/lez-programs: programs/amm`, deployed on the legacy testnet with a published image id, alongside `programs/token`, `programs/twap_oracle` and `programs/token_mint_authority`. The repository also holds `programs/ata` and `programs/stablecoin`, which its deployment record does not list.

It is written against neither the actor interface nor plan/apply. It pins `lee_core` at tag `v0.2.5-rc2` and uses `ChainedCall`, `Claim` and `lee_core::account::Data`, which is the whole-account interface LEZ ran before `v0.3.0`. So this entry describes a program a reader can use on the legacy testnet but cannot read as an example of the model in Part III, or of plan/apply either. See [Which interface you are writing for](../understand/which-interface.md) for the translation.

## The accounts

| Account | Placement | Holds |
|---|---|---|
| Config | public PDA, `compute_config_pda` | the AMM's own configuration and namespace |
| Pool | public PDA, `compute_pool_pda` | `PoolDefinition`: the pair, the vaults, the LP definition, reserves, fee tier |
| Vault A, Vault B | public PDAs, `compute_vault_pda` | token holdings spendable only by the AMM's seed |
| LP definition | public PDA, `compute_liquidity_token_pda` | a token definition the AMM mints and burns by seed |
| LP lock holding | public PDA, `compute_lp_lock_holding_pda` | the permanently locked minimum liquidity |
| Protocol fee | public PDA, `compute_protocol_fee_pda` | accrued protocol fees, withdrawable by authority |
| Trader holdings | any: public or private token holdings | the trader's side |

Every pool account is public. The pool's reserves, its price and every trade against it are on chain in the clear. What a private transaction hides is which trader traded, never what was traded.

## The instructions

`initialize`, `new_definition`, `add`, `remove`, `swap`, `sync`, `update_config`, `withdraw_protocol_fees`, `create_price_observations`, `create_oracle_price_account`.

Swapping takes `(swap_amount_in, min_amount_out)` and computes the output at execution from live reserves, through `amm_core::swap_exact_in_amounts`. The same core function is what an off-chain client calls to preview a quote, so the preview and the settlement agree by construction. `swap_exact_out_amounts` is the other direction.

Fees are tiered, with `FEE_TIER_BPS_30` against `FEE_BPS_DENOMINATOR`, and a share accrues to the protocol fee account via `protocol_fee_amount`. `MINIMUM_LIQUIDITY` is locked permanently on the first deposit, in the LP lock holding, so the pool can never be fully drained and re-seeded at a manipulated price.

A TWAP oracle is maintained in price observation accounts and consumed by other programs, `programs/stablecoin` among them.

## What it leaks

| Trader input | Trader output | Transaction | Chain sees |
|---|---|---|---|
| public holding | public holding | public | the trade and the trader |
| private holding | private holding | private | the trade in full: pair, direction, size, price. Not the trader |
| private holding | public holding | private | the trade, and the public recipient |

The middle row is the whole privacy story of an AMM on LEZ, and it is worth being blunt about: a private swap hides who traded, not what was traded. The pool is public because an AMM without a public price is not an AMM, so every swap publishes its own size and direction. A trader who swaps an unusual amount is identifiable by that amount alone, across transactions, without anyone breaking any cryptography.

[The idea catalog](ideas.md) records the stronger version as a negative result: an AMM with hidden reserves does not work under this model.

## A design note worth keeping

The plan/apply edition of this guide built its AMM chapter on a different swap: the trader named an exact `amount_out`, and the pool's guard was the inequality `amount_out <= quote` against live reserves. An offer prepared at one price settled at another if the curve still covered it, and was refused otherwise, which made it the clearest illustration in that book of why a prepared private transaction survives public state moving under it.

The shipped AMM does not work that way, and the fixed-offer design is still the better teaching example for that property. If this chapter is ever rewritten against the actor model, the question to settle first is whether it documents the pool that exists or teaches the pattern that explains preparation. Both are defensible; doing both in one chapter is what produces the confusion this note exists to prevent.

The property itself is demonstrated without an AMM by `two_deshielded_transfers_to_one_recipient_compose_at_settlement` in `lee/state_machine/src/state/tests/privacy_preserving.rs`: two transactions prepared against a recipient balance of 400, settling against 437 and 448.
