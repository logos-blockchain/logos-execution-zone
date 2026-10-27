# The pattern language

Every design in the catalog is assembled from a small set of moves. This chapter names them, shows the minimal code for each, and says which privacy placements they survive. Later chapters refer back here by name.

## 1. Proposal and guard

The plan cannot read state, so the instruction **proposes** what the state is or should become and the shard's own apply **confirms** it. The proposal travels in the effect; the guard is the apply.

```rust
// plan
plan.effect(&pool, &Effect::Swap(binding));           // proposal: these amounts, these vaults
// apply on the pool shard
let pool = PoolDefinition::try_from(pre_data)?;
assert!(binding.amount_out <= quote(pool, binding.amount_in));   // guard
```

Works everywhere. On a public shard in a private transaction the guard runs at settlement, in the clear, which is what makes a prepared transaction "conditionally valid": it settles if the guard still passes.

Rule of thumb: every value the plan takes from the instruction and later relies on must be pinned by a guard on a shard that knows the truth, or the plan is trusting the caller.

## 2. Two-sided binding

A cross-shard invariant (sender has enough, recipient gets the same amount; supply and holding move together) is enforced by emitting **one effect per side, each carrying the shared proposal**, so that both applies check it independently.

```rust
plan.effect(&definition, &Effect::BurnSupply { kind, amount });
plan.effect(&holding,    &Effect::BurnHolding { descriptor, amount });
```

If either side disagrees the transaction fails, and since the two effects carry the same numbers the join is exact. This is how the token program keeps supply and holdings consistent without ever seeing both at once.

## 3. Inspect, do not write

A check on another program's shard is an effect that returns `None`:

```rust
plan.inspect(&clock, clock.program_account_id, &Guard::TimestampIs(t));
plan.inspect(&vault, NATIVE_TOKEN_PROGRAM_ID, &Guard::BalanceIs(b));
```

Any program can inspect any shard handed to it. This is how a program reads the clock, checks a vault's native balance, verifies a config it does not own, or asserts an ATA is empty. In a private transaction an inspect on a public shard is a public effect (its guard bytes are visible) evaluated at settlement.

## 4. Seed-authorized custody

Value the program controls sits in a PDA; the program spends from it by delegating the seed in a chained call.

```rust
let vault = AccountId::for_public_pda(&input.self_account_id, &vault_seed);
plan.call(custody_transfer(vault, vault_seed, recipient, amount));
```

Every withdrawal guard must live in the program that delegates. Private variant: `for_private_pda(self, seed, npk, vpk, id)` gives one vault per key holder; the program authorizes it the same way, and only the key holder can see it.

## 5. Config pinning

Global parameters (an authority, a minter, a route, a fee rate) live in the program's shard on a fixed-seed PDA, written once with `write_once`, and every instruction that depends on them pins the proposed value with an effect on that PDA.

```rust
// genesis / setup
plan.effect(&config, &Effect::InitConfig(bytes));          // apply: write_once(pre_data, bytes)
// use
plan.effect(&config, &Effect::Route { outbox, target });   // apply: assert config says so; None
```

`write_once` makes setup idempotent (genesis replay) and refuses a different value. Updates, when allowed, gate on `is_authorized` of an authority account named in the config and checked in apply.

## 6. Caller pinning

An instruction meant for one caller checks `caller_account_id`, either against a constant (`Some(self_account_id)` for internal steps, `None` for top-level-only) or against a config value via an effect.

```rust
assert_eq!(input.caller_account_id, Some(input.self_account_id));   // internal step
assert!(input.caller_account_id.is_none());                          // no chaining into me
plan.effect(&config, &Effect::Mint { caller: input.caller_account_id, .. }); // config decides
```

Without it, any program with the right accounts can drive the instruction.

## 7. Self-call for post-conditions

To check an invariant *after* chained calls have run, chain into yourself last with an instruction that only accepts `caller == self`.

```rust
plan.call(custody_transfer(vault, seed, receiver, amount));   // 1: lend
plan.call(ChainedCall { program_account_id: callback, .. });  // 2: arbitrary logic
plan.call(ChainedCall::new(input.self_account_id, vec![vault_selector],
          &Instruction::InvariantCheck { min_vault_balance }));   // 3: assert
```

Calls run depth first in emission order, so step 3 sees whatever steps 1 and 2 left. This is the flash-loan shape (`flash_swap_initiator.rs`) and the general answer to "there is no return value from a chained call".

## 8. Receipt shard

A one-shot operation (deposit id, claim, ticket, vote) writes a marker into a PDA derived from the operation's key; the apply refuses if the shard is non-empty.

```rust
let receipt = AccountId::for_public_pda(&self_id, &H(op_id));
plan.effect(&receipt_meta, &Effect::RecordOnce);   // apply: assert!(pre_data.is_empty()); Some([1])
```

Public receipts are visible (someone claimed op `X`). A private receipt is a private PDA of the claimant: the program can still enforce one-per-key, but nobody else sees the claim.

## 9. Init-only receive

To receive privately, a design never updates a recipient's account; it initializes a new one. The recipient publishes `(npk, vpk)`, the sender picks an identifier, the wallet lists the recipient as `PrivateForeign { npk, vpk, kind: Regular(identifier) }`.

```rust
// in a program: "pay recipient r" becomes "credit the account the caller listed",
// and the caller chooses to list a fresh private account of r
plan.call(custody_transfer(vault, seed, recipient.account_id, amount));
```

The program does not know or care that the recipient is a fresh private account. Sweeping many received accounts into one is a separate, owner-driven transaction.

## 10. Family slots

A private PDA family `(program, seed, npk, vpk, *)` is a namespace of accounts the program controls and one key holder can see. Use the identifier as a slot: one per deposit, per epoch, per ticket. The program authorizes any member by the seed; the wallet discovers them by syncing.

## 11. Secret in the instruction

Instruction data of a private transaction is never published. A program can therefore take a **secret** in its instruction, derive a public value from it in `plan`, and pin that value with a guard: prove knowledge of a preimage, of a share, of a credential, without the secret leaving the prover.

```rust
let tag = sha256(&instruction.secret);
plan.inspect(&registry, registry_program, &Guard::IsRegistered(tag));
```

Anything derived from the secret that reaches a public effect is public; the secret itself is not. Public transactions do not get this: their instruction data is on chain.

## 12. Commutative public effects

When several private transactions may target the same public shard, design the effect so that applies commute and the guard is monotone: `Credit(n)` rather than `Set(total)`, `Increment` rather than `Store(count + 1)`, `amount_out <= quote` rather than `amount_out == quote`. Then prepared transactions from different users settle in any order.

## 13. Windows for expiry

`plan.timestamp_window(..deadline)` or `plan.block_window(..height)` bounds how long a prepared transaction can be settled. Use it on anything prepared ahead (offers, votes, approvals) so a stale one cannot resurface.

## 14. Clock proposal

Read time by proposing it: instruction carries `now`, a clock guard pins it, the program's own effects use it. In private transactions the guard runs at settlement, so `now` is "no earlier than the clock at settlement" for `>=` guards and exact for `==` guards (which will rarely settle).

## 15. Public bulletin, private actor

A program whose state must be shared and concurrently written (a tally, a registry, an order list) keeps that state **public**, and lets private accounts act on it through private transactions whose public effects are the only visible trace. Combine with 11 and 12: the actor proves eligibility from a secret, the effect is commutative, the actor stays hidden and the state stays live.

## 16. Private state, single actor

State that only one party ever writes (a personal ledger, a subscription, a position) goes in a **private** account or private PDA. Everything about it is hidden, including that it changed. The program can still enforce rules over it, and the party can still interact with public state through deferred effects.

## 17. Bind by content, spend by seed, never derive an address

A program that computes `for_public_pda(self, seed)` in its plan and compares it to a handle has silently decided that account is public. The same program cannot serve a private placement of that account, because the private address also contains keys the plan does not have. To stay placement-free:

- **Spend by seed.** Delegate `pda_seeds` in the chained call and let the runtime decide whether the handle is your PDA under that seed. It resolves the public derivation and the private witness binding for you, and refuses everything else.
- **Bind by content.** When two of your accounts must belong together (a config and its vault, a proposal and its board), write each one's account id into the other at init, `write_once`, taking the ids from the `AccountMeta`s you were handed. Pin the pair with guards ever after.
- **Pin by guard, not by address.** "Is this the real config?" becomes "does the vault's record say so?", which is a guard the apply can answer from its own bytes.

Address derivation in a plan is still right for accounts that are public **by design**: receipt PDAs keyed by a nullifier, name-registry entries, the clock accounts. Use it there and nowhere else.

## 18. Deposit key

To let a trusted party pay into one private account of yours repeatedly, and see its balance, without letting them spend: share the account's `nsk` and viewing seed, keep `ask`. They build `Update` witnesses with `ask: None`; the account is unauthorized in their calls, so credits work and debits fail. Details and caveats in [Deposit keys](../foundations/private-accounts.md#deposit-keys-sharing-nsk-and-vsk-without-ask). Use it where init-only receive (pattern 9) would produce too many slots to sweep, and where the payer is trusted not to grief.

## Anti-patterns

- **Trusting the instruction.** A plan that debits `amount` from the caller's proposed balance without a guard on the real shard is a mint.
- **Reading in plan.** Not possible, but people try to smuggle state into instruction data and forget the guard.
- **Set instead of update.** `Effect::SetBalance(new)` on a shared public shard makes concurrent private transactions clobber each other or fail at settlement; use deltas.
- **Big effects on public shards.** Everything in them is public forever.
- **Storing the same fact in two shards.** Two applies cannot see each other; keep one source of truth and inspect it.
- **Forgetting `caller_account_id`.** A privileged instruction without a caller check is callable from any program, including a peer zone's inbox.
- **Deriving your own PDAs' addresses in `plan`.** It pins the placement to public. See pattern 17.
- **Guards that depend on who is asking.** Settlement applies public effects with no notion of the submitter; a guard must be decidable from the effect bytes and the shard alone.
