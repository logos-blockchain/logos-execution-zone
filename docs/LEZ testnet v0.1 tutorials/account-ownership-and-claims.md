This tutorial explains a subtle account-ownership rule that affects any LEZ program where a signer submits more than one transaction. By the end, you will understand:

1. What `NonDefaultAccountWithDefaultOwner` is and when it fires.
2. Why a signer's first transaction to a program succeeds but the second can fail.
3. The claim-on-first-touch pattern that fixes it, and how LEZ's own `authenticated_transfer` uses the same pattern.

---

## The rule

When a signer submits a transaction to a LEZ program, the program receives the signer's account as a pre-state input. If the signer has never transacted with this program before, their account is in its **default** state: default nonce, default balance, and crucially, a **default program owner**.

The first transaction succeeds: the program writes to the account (a balance change, a shard update, or just reading it), and the sequencer advances the signer's nonce. The account is now **non-default** (the nonce changed), but the `program_owner` field is still **default** (no program has claimed ownership).

On the signer's **second** transaction to the same program, the sequencer checks: the account is non-default, but `program_owner` is default. This is the `NonDefaultAccountWithDefaultOwner` condition, and the transaction is rejected:

```
NonDefaultAccountWithDefaultOwner { account_id: ... }
```

The error means: "this account has been used before (non-default nonce), but no program has taken ownership of it (default owner), so writing to it again is not allowed."

## The fix: claim on first touch

Programs that expect a signer to submit multiple transactions must **claim** the signer's account on the first transaction. In the LEZ guest API (v0.2.x), this is done by setting the account's post-state to claim the account if it is still default:

```rust
// v0.2.x API (lee_core / nssa_core)
AccountPostState::new_claimed_if_default(acc, Claim::Authorized)
```

This tells the sequencer: "if this account is still in its default state, set me (this program) as its owner." After the claim, the account's `program_owner` is no longer default — it is this program — and subsequent transactions from the same signer succeed.

The pattern is **claim on first touch, plain write after**. The claim is idempotent: if the account is already claimed (non-default owner), the claim is a no-op and the write proceeds normally.

## Where LEZ uses this itself

LEZ's own `authenticated_transfer` program uses the same claim-on-first-touch pattern for the owner-at-Init step: when the program is initialised, it claims the owner's account so that subsequent transfer transactions from that owner succeed. The pattern is the same; the difference is that `authenticated_transfer` claims at Init, while a permissionless program (like a registry that accepts registrations from arbitrary signers) must claim in every instruction that writes to a signer's account, because there is no Init step with a known owner.

## When you need this

You need the claim pattern if your program:
- Accepts transactions from signers who are not the program owner.
- Expects any signer to submit **more than one** transaction to the program.
- Is permissionless (anyone can call it without a setup step).

You do **not** need it if:
- Each signer only ever submits one transaction to your program.
- Your program only reads accounts and never writes to them.
- Your program is the sole owner of all accounts it touches (e.g., PDAs it created).

## Practical example

A registry program that lets anyone register entries (like an OSM region registry) must use the claim pattern in its `Register` instruction, because each registrar may register multiple regions in separate transactions:

```rust
// In the Register instruction's post-state:
let registrar_post = AccountPostState::new_claimed_if_default(
    registrar_pre,
    Claim::Authorized,
);
```

Without this, the registrar's first `Register` tx succeeds, but their second fails with `NonDefaultAccountWithDefaultOwner`. With it, the program claims the registrar's account on the first registration, and all subsequent registrations from that signer succeed.

## Summary

| Scenario | Without claim | With claim |
|---|---|---|
| Signer's 1st tx | Succeeds | Succeeds (claims the account) |
| Signer's 2nd tx | Fails: `NonDefaultAccountWithDefaultOwner` | Succeeds (owner is now the program) |
| Signer's 3rd+ tx | Fails | Succeeds |

The claim-on-first-touch pattern is the LEZ equivalent of Solana's "close and reopen" or "assign and delegate" patterns: it establishes program ownership of an account so that repeated writes from the same signer are valid.
