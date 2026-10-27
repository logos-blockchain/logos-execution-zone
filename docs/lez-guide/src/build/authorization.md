# Authorization and program-derived accounts

A handler receives one flag, `input.is_authorized`. This chapter says where it comes from, what it means, and what it does not mean. The last part matters most.

## Where the flag comes from

The engine sets `is_authorized` to true when at least one of these holds for the receiving account (`Execution::authorize`, `lee/state_machine/core/src/execution_state.rs`):

| Source | Applies to | How |
|---|---|---|
| Signature | public key-owned accounts | the owner signed the transaction |
| Spending key | private regular accounts | the owner supplied the authorization key to the proof |
| Seed grant | PDAs, public and private | the sending program attached the PDA's seed to its SyncMessage |
| Inherited grant | any account granted earlier in the same chain of SyncMessages | the grant travels down the SyncMessages that follow it |

An AsyncMessage never carries a grant.

## Program-derived accounts

A PDA is an account with no key. Its id is derived from a program's id and a seed:

```rust
AccountId::for_public_pda(&program_account_id, &seed)
```

Only that program can authorize it. It does so by attaching the seed to a SyncMessage:

```rust
const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

fn handle_message(input: &ReceiveInput, callee: AccountId) -> Response {
    Response::keep_state().send(
        SyncMessage::new(Actor::new(input.receiver.account_id, callee), &greeting)
            .with_pda_seeds(vec![PDA_SEED]),
    )
}
```

This is `examples/program_deployment/methods/guest/src/bin/tail_call_with_pda.rs`. The engine checks that the seed, hashed with the **sending** program's id, gives the receiving account. If so, the receiver sees `is_authorized == true`.

A private PDA works the same way. Its id also includes the holder's public keys, so several groups can each have their own private PDA for the same program and seed.

## Custody

Custody is the main use of a PDA. A program that must hold funds keeps them in the native balance actor of a PDA it controls, and releases them with a seed grant:

```rust
pub fn custody_transfer(from: AccountId, seed: PdaSeed, to: AccountId, amount: Balance) -> SyncMessage {
    SyncMessage::new(Actor::native_balance(from), &Message::Transfer { to, amount })
        .with_pda_seeds(vec![seed])
}
```

The bridge pays deposits this way (`lez/programs/bridge/src/main.rs`). No key exists that could move those funds. Only the program's own logic can.

When several users share one program, derive the seed from something that identifies the instance. Otherwise one user's instance could grant the seed of another's.

## Knowing who sent a message

Authorization is about the receiving account. Identity is about the sender. They are separate checks.

- `input.from` is the sending actor, or `None` when the transaction's author submitted the message.
- `input.from_own_program()` is true when the sender is an actor of the same program.

Use the first to accept messages only from a known actor. Use the second for a program's internal messages:

```rust
Message::Credit(amount) => {
    if !input.from_own_program() {
        return Err(TransferError::ForeignCredit { account_id });
    }
    ...
}
```

A credit must come from the native token program itself, or anyone could mint.

**An account id alone identifies nobody.** Anyone can deliver a message to any program's actor on any public account, without that account's authorization. A program that forwards whatever it receives would then send messages "from" that account. So when a handler wants to know that a specific person is speaking, it compares the whole sending `Actor`: the account, and a program it trusts to have checked `is_authorized`. The usual choice is the program itself: each participant speaks through their own actor of the program (a "seat"), and the receiving side checks `from_own_program()` plus the account id.

> **Improvement over plan/apply.** A program used to learn which *program* had called it and, per account, whether it was authorized. Now the sender is an actor, an account and a program, and a private sender can present a blinded address. That one field replaces techniques each program built by hand: hashes of secrets registered in public state, Merkle membership paths carried in the instruction, and receipt accounts written to stop reuse.

## What `is_authorized` does not mean

**It does not mean "the owner asked for this message".** It means "the owner's credential is present in this transaction, or a program granted this account".

The difference is the model's main footgun. It shows up in two ways.

**A program inside a transaction you signed.** Alice signs a transaction whose root goes to some program P. Every actor on Alice's account now sees `is_authorized == true` for the whole transaction. If P's handler sends `Transfer` to Alice's token actor, the token program honours it. Signing a transaction lends your authority to every program that runs in it, over every account that signed.

**A stored message collected with the spending key.** Anyone can send an async message carrying any bytes to any registered address. Mallory can send `Transfer { to: mallory, .. }` to Alice's private balance actor. Nothing happens until Alice collects it. If she collects it with her spending key attached, the transfer runs.

The protocol leaves the second case to the owner on purpose. A private account has two keys: one is enough to receive, the other authorizes spending. Collecting with the spending key means **"I accept what this message asks"**. That is a useful primitive (see [Payment requests](../catalog/requests.md)), and it is dangerous as a default.

Rules that follow:

- **For program authors.** If an operation must be started by the owner and nobody else, check both `is_authorized` and `input.from.is_none()`. If another program may start it, decide which one and check `input.from`.
- **For wallet authors.** Collect without the spending key unless the user has seen the message and agreed to it. The reference wallet always collects without it.
- **For users.** A transaction is only as trustworthy as every program it runs.
