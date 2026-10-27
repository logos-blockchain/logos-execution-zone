# Multisig, in every public/private combination

**Shows:** the seat (4) · the proof-carrying message (7) · pseudonym (8) · async message for strangers (9) · seed-authorized custody (13) · group-owned private PDA (18)

## Goal

A vault that pays out only when `k` of its `n` members approve. The same program must work when the vault is public or hidden, and when each member is public or hidden, in any mix.

This entry is the clearest tour of the model. One handler, three design choices, four placements.

## The three choices

**1. The vault is a PDA.** The vault's state and its funds live on an account with no spending key. Only the multisig program can move the funds, by granting the PDA's seed (pattern 13). For a hidden vault, the PDA is private and its keys come from a group secret (pattern 18).

**2. A member is a seat.** Each member has an actor of the multisig program on their own account: `(member_account, multisig)`. The member tells the seat to approve. The seat tells the vault. The vault checks that the message comes from its own program and from a registered seat (patterns 4 and 7).

**3. Seats speak by AsyncMessage.** An AsyncMessage to a public vault is delivered at once. An AsyncMessage to a hidden vault is stored for a member to collect. The seat's code is the same either way (pattern 9).

> **Improvement over plan/apply.** A hidden member used to be the hash of a secret written into the vault's configuration, checked by its own code path, and the members of a fully hidden vault took turns writing its shared state. Here a hidden member is a seat like any other, at a blinded address, and approving is sending a message. Only the member who operates the vault writes its state.

## Actors

| Actor | What it holds | Placement |
|---|---|---|
| `(vault, multisig)` | threshold, seat list, approvals so far | public PDA, or group-owned private PDA |
| `(vault, native)` | the funds | same account as above |
| `(member, multisig)`: a seat | which vault it belongs to | on each member's account, public or private |

The member list holds seat **addresses**. A private member registers a blinded address, so the list never names their account (pattern 8).

## Messages

```rust
enum Message {
    /// To a seat, by its owner: approve paying `amount` to `to` out of `vault`.
    Approve { vault: AccountId, to: AccountId, amount: u128 },
    /// From a seat to the vault.
    Approved { to: AccountId, amount: u128 },
}
```

There is no separate "propose" step. A payment exists once one member has approved it.

## Handler

```rust
fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let program = input.receiver.program_account_id;
    match message {
        // A member's seat: check the owner, tell the vault.
        Message::Approve { vault, to, amount } => {
            assert!(input.is_authorized && input.from.is_none(), "only the member uses the seat");
            Response::keep_state()
                .send_async(Actor::new(vault, program), &Message::Approved { to, amount })
        }

        // The vault: count approvals from its registered seats.
        Message::Approved { to, amount } => {
            assert!(input.from_own_program(), "only seats speak to a vault");
            let seat = input.from.unwrap().account_id;
            let mut vault = Vault::from_bytes(&input.pre_state);
            assert!(vault.seats.contains(&seat), "not a member");

            let approvals = vault.approvals.entry((to, amount)).or_default();   // a set of seats
            approvals.insert(seat);
            if approvals.len() < vault.threshold {
                return Response::set_state(vault.to_bytes());
            }

            // Threshold met: pay from the vault's own balance, by seed.
            vault.approvals.remove(&(to, amount));
            Response::set_state(vault.to_bytes()).send(native_token::custody_transfer(
                input.receiver.account_id, vault.seed, to, amount))
        }
    }
}
```

The vault's settings (`seats`, `threshold`, `seed`) are written once when it is created. That first write must check that the seed derives the vault's own account, or no payout could ever be made.

A seat is recognised by its address, so a member must speak to a vault from the **same** address every time. A private member's wallet has to reuse the blinding factor it registered with, not pick a fresh one per message.

The payout is the native token's `Transfer`, which sends the credit to the recipient as an async message. So the recipient can be public or private too, with no extra code.

## The four placements

### Public vault, public members

{{#include ../diagrams/multisig-all-public.svg}}

An ordinary multisig. Each approval is a signed public transaction: the member's seat runs, its AsyncMessage to the declared vault is delivered at once, and the last approval pays in the same transaction.

### Public vault, hidden members

{{#include ../diagrams/multisig-hidden-members.svg}}

The vault's balance and pending payments are public. A hidden member approves with a private transaction. Their seat runs inside the proof and its AsyncMessage crosses to the public vault, carrying the seat's blinded address as sender.

The vault learns that seat number three approved. Nobody learns who holds seat number three. Public and hidden members can sit on the same vault.

### Hidden vault, hidden members

{{#include ../diagrams/multisig-hidden-vault.svg}}

The vault is a group-owned private PDA. Approvals are sealed AsyncMessages, stored on chain. Any member who holds the group secret collects them, one per transaction. When the collected approval is the `k`-th, the same transaction pays.

An observer sees sealed messages and unlinkable notes. If the recipient is private as well, they see nothing else at all. A hidden vault paying a public recipient reveals the amount and the recipient, and still hides the vault.

### Hidden vault, public members

{{#include ../diagrams/multisig-hidden-vault-public-members.svg}}

This works and is the weak combination. A public seat's AsyncMessage is stored in the clear, so each approval is a readable message from a known account to the vault's address. The vault's balance stays hidden. Its membership and what it approves do not.

## What the group secret does and does not give

Every member of a hidden vault holds the same keys for it. That lets any of them **operate** the vault: read its state and collect its messages. It does not let any of them **spend**. A PDA has no spending key, and the program grants the seed only when the threshold is met.

So the shared secret is a liveness tool, not a trust assumption about funds.

## What leaks

| Placement | Balance | Pending payments | Who approved | That a payout happened |
|---|---|---|---|---|
| public vault, public members | yes | yes | yes | yes |
| public vault, hidden members | yes | yes | pseudonyms only | yes |
| hidden vault, hidden members | no | no | no | only to a public recipient |
| hidden vault, public members | no | no | yes | only to a public recipient |

## Costs

A hidden vault pays for its privacy in transactions. A payment that needs `k` approvals takes `k` private transactions from members, and `k` collecting transactions by whoever operates the vault. Each is a proof.

Two members who try to advance the vault at the same moment both spend the same state. One transaction lands and the other fails and must be rebuilt. A hostile member can do this on purpose and stall the vault. The group secret cannot take funds, but it can deny progress.

## Going further

- **Signatures instead of seats.** Members sign the payment off chain and one message carries `k` signatures. One transaction per payment, at the price of signature checks in the handler.
- **Any action, not only payments.** Let an approval carry `{ target, message }` and have the vault send it with its seed. The vault can then hold tokens, vote, or sit on another multisig.
- **What does not work: a hidden vault that anyone can execute.** Only a key holder can run a private handler, so a hidden vault always needs one of its members to operate it.
