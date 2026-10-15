# A minimal token

**Shows:** tell, do not write (1) · internal messages (3) · cast for strangers (9) · receive without failing (6)

## Goal

A token with balances and transfers, in one screen of code. It is the native token's design (`lee/state_machine/core/src/native_token.rs`) with minting added, and it is the smallest program that shows why the actor model suits money.

## Actors

| Actor | What it holds | Authorized by |
|---|---|---|
| `(holder, token)` | a balance | the holder |
| `(ISSUER, token)` | a balance, and the right to mint | the issuer |

One actor per holder. No central ledger.

## Messages

```rust
enum Message {
    /// Needs the holder's authorization.
    Transfer { to: AccountId, amount: u128 },
    /// Needs the issuer's authorization, at the issuer's actor.
    Mint { to: AccountId, amount: u128 },
    /// Only from another actor of this program.
    Credit(u128),
}
```

## Handler

```rust
fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let me = input.receiver;
    let balance = decode_balance(&input.pre_state);     // empty state reads as zero
    let token_actor = |account_id| Actor::new(account_id, me.program_account_id);

    match message {
        Message::Transfer { to, amount } => {
            assert!(input.is_authorized, "not your balance");
            let rest = balance.checked_sub(amount).expect("insufficient balance");
            Response::set_state(encode_balance(rest))
                .cast(token_actor(to), &Message::Credit(amount))
        }
        Message::Mint { to, amount } => {
            assert!(input.is_authorized && me.account_id == ISSUER, "only the issuer mints");
            Response::keep_state().cast(token_actor(to), &Message::Credit(amount))
        }
        Message::Credit(amount) => {
            assert!(input.from_own_program(), "a credit comes from the token itself");
            Response::set_state(encode_balance(balance + amount))
        }
    }
}
```

That is the whole program.

## What to notice

**The sender debits itself and tells the recipient.** No handler ever touches two balances. Supply is conserved because the only way to send `Credit` is one of the two arms above.

**`Credit` trusts its sender, not a signature.** `from_own_program()` is the entire mint protection.

**The credit is a Cast.** To a public recipient it lands in the same transaction. To a private recipient it waits in their mailbox. The handler does not know which.

**Receiving needs no setup.** An empty state reads as zero, so the first credit creates the balance.

> **Improvement over plan/apply.** A transfer used to be one call that listed both holdings and emitted a matching effect on each, so the sender's transaction needed the recipient's account as an input. Now the sender's actor does not need the recipient to exist yet, to be public, or to be online.

## Public and private

{{#include ../diagrams/tokens-four-transfers.svg}}

| Sender | Recipient | What an observer sees |
|---|---|---|
| Public | Public | everything |
| Public | Private | sender, amount, destination address |
| Private | Public | amount, recipient; the sender is hidden or a pseudonym |
| Private | Private | a sealed message |

The program has no code for any of these four cases. They come from which accounts the user picks.

## Going further

- **The shipped token** (`logos-blockchain/lez-programs: programs/token`) adds token definitions, NFTs, burning and a **notify hook**: a credit can carry `notify { to, payload }`, and the receiving balance then Calls `to` to say "you were paid". That turns "pay, then act" into one message (pattern 19).
- **Custody by other programs.** `Transfer` checks only `is_authorized`, so a program can move tokens it holds on a PDA by granting the seed (pattern 13).
- **The same check is the footgun.** `is_authorized` does not say who sent the `Transfer`. Read [what it does not mean](../foundations/authorization.md) before copying this handler.
