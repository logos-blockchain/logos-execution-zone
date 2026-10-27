# Payment channels

## Goal

Many small payments between two parties with one transaction to open and one to settle, in the style of Bitcoin's Lightning. The payments in between are signed messages exchanged off chain: instant, free, and invisible to everyone else.

This entry is the smallest version, a one-way channel from a payer to a recipient. It uses seed-authorized custody (pattern 4), the proposal-and-guard discipline (pattern 1), a window for expiry (pattern 13), and a secret in the instruction for a private recipient (pattern 11).

## Accounts

| Account | Placement | Contents |
|---|---|---|
| Channel | any public account the payer chooses | `Channel { voucher_key, gate, refund_gate, capacity, paid, expiry_ms, vault, vault_seed }` |
| Vault | a PDA of the program under `vault_seed` | the channel's funds, in its native shard |
| Destination | a public account, or a fresh private slot under the recipient's key | credited |

`voucher_key` is a signing key the payer creates for this one channel. It is not an account key and links to nothing.

`gate` says who may direct a payout, as in [Payment streams](streams.md): `Account(id)` pays one fixed public account, `Secret(H(s))` lets whoever knows `s` choose the destination in a private transaction.

## Off chain

A **voucher** is the payer's signature over `(channel, total)`: "this channel owes the recipient `total` so far".

To pay 1 more, the payer signs a voucher for `total + 1` and hands it to the recipient. Nothing touches the chain. The recipient keeps only the latest voucher.

## Instructions and effects

```rust
enum Instruction {
    Open   { voucher_key: [u8; 32], gate: Gate, refund_gate: Gate, capacity: u128,
             expiry_ms: u64, vault_seed: PdaSeed },
    Redeem { total: u128, signature: [u8; 64], due: u128, secret: Option<[u8; 32]>,
             vault_seed: PdaSeed },
    Close  { refund: u128, expiry_ms: u64, secret: Option<[u8; 32]>, vault_seed: PdaSeed },
}
enum Effect {
    OpenChannel(Channel),                                  // write_once
    Redeem { total: u128, signature: [u8; 64], due: u128, // guard + update
             gate_proof: GateProof, vault: AccountId, vault_seed: PdaSeed },
    Close  { refund: u128, expiry_ms: u64, gate_proof: GateProof, vault: AccountId,
             vault_seed: PdaSeed },
}
```

`due` and `refund` are proposals. `plan` cannot read how much the channel has already paid, so the caller states the amount and `apply` checks it.

## A simple version

```rust
fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Redeem { total, signature, due, secret, vault_seed } => {
            // accounts: channel, vault (native), destination (native)
            let [channel, vault, destination] =
                <&[_; 3]>::try_from(input.accounts.as_slice()).unwrap();
            let gate_proof = match secret {
                Some(s) => GateProof::Secret(sha256(&s)),
                None => GateProof::Account(destination.account_id),
            };
            plan.effect(channel, &Effect::Redeem {
                total, signature, due, gate_proof, vault: vault.account_id, vault_seed });
            plan.call(custody_transfer(vault.account_id, vault_seed, destination.account_id, due));
        }
        Instruction::Close { refund, expiry_ms, secret, vault_seed } => {
            /* same shape, with Effect::Close, plus: */
            plan.timestamp_window(expiry_ms..);
        }
        Instruction::Open { .. } => { /* OpenChannel on the record, then a native transfer of
                                         `capacity` from the payer to the vault */ }
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::OpenChannel(c) => Some(write_once(pre_data, c.to_bytes())),
        Effect::Redeem { total, signature, due, gate_proof, vault, vault_seed } => {
            let mut c = Channel::from_bytes(pre_data);
            assert!(c.gate.admits(&gate_proof), "not the recipient");
            assert_eq!((c.vault, c.vault_seed), (vault, vault_seed), "not this channel's vault");
            c.voucher_key.verify(&voucher_bytes(&c, total), &signature).expect("bad voucher");
            assert_eq!(Some(due), total.checked_sub(c.paid), "pay exactly the new part");
            c.paid = total;
            Some(c.to_bytes())
        }
        Effect::Close { refund, expiry_ms, gate_proof, vault, vault_seed } => {
            let mut c = Channel::from_bytes(pre_data);
            assert_eq!(expiry_ms, c.expiry_ms, "the window must be the channel's own expiry");
            assert!(c.refund_gate.admits(&gate_proof), "not the payer");
            assert_eq!((c.vault, c.vault_seed), (vault, vault_seed));
            assert_eq!(refund, c.capacity - c.paid, "refund exactly the rest");
            c.paid = c.capacity;
            Some(c.to_bytes())
        }
    }
}
```

`Close` is only valid from the expiry on. `plan` cannot read the expiry, so the caller states it, `plan` turns it into a validity window, and `apply` checks that it is the channel's own.

`Open` funds the vault in the same transaction that writes the record, so the capacity in the record is real by construction.

All public:

{{#include ../diagrams/channels-all-public.svg}}

Private recipient:

{{#include ../diagrams/channels-one-way.svg}}

Private payer, described in the next section:

{{#include ../diagrams/channels-private-payer.svg}}

## Funding from a private account

The payer does not have to appear on chain. `Open` can be a private transaction.

| Account in `Open` | Placement | What happens to it |
|---|---|---|
| Channel record | public | `OpenChannel` is applied at settlement, in the clear |
| Vault | public PDA | credited with `capacity` at settlement, in the clear |
| Payer's balance | **private** | debited inside the proof |

The transfer from the payer to the vault is an ordinary deshield: the debit is proven, the credit is a public effect. The chain sees that a channel with this capacity was opened. It does not see by whom.

Two settings decide whether the payer stays hidden afterwards:

- **`refund_gate`.** Use `Secret(H(s))`. After the expiry the payer closes the channel in a private transaction, proves knowledge of `s`, and receives the rest in a fresh private slot. An `Account(id)` gate would name a public account.
- **`voucher_key`.** Make a new key for each channel. It appears in the record, and a reused key links the payer's channels to each other.

> **With actors.** Anyone can redeem to a private recipient with a plain public transaction, and the refund is pushed to a private payer: both wait in a mailbox until collected. The amount due is computed by the handler, not proposed by the caller. In exchange, the channel can no longer fund itself in `Open` or see its own balance.

## Why neither side can cheat

- The recipient can redeem only what the payer signed, and an older voucher pays nothing, because `due` is measured from what was already paid.
- The payer cannot take funds back before the expiry. The vault is a PDA: no key moves it, only a seed delegated by this program after its own checks.
- Checking a signature in `apply` is ordinary code. The stake program does the same for its approvals (`lez/programs/sequencer_stake/src/main.rs`).

## Interoperability matrix

| Payer | Recipient | Redeem tx | Chain sees |
|---|---|---|---|
| Pub | Pub (`Account` gate) | public, sent by anyone holding a voucher | payer, recipient, capacity, the redeemed total |
| Pub | Priv (`Secret` gate) | private, by the recipient, into a fresh slot | payer, capacity, the redeemed total; **not the recipient** |
| Priv | Pub | public | recipient, capacity, total; **not the payer** (the vault was funded from a private account) |
| Priv | Priv | private | capacity and total only |

## What leaks

In every row: that a channel exists, its capacity, the voucher that was redeemed (its `total` and signature are effect bytes on a public shard) and the time. Never: how many payments were made, their sizes, or what they were for.

Compare with a [payment stream](streams.md), which publishes every withdrawal.

## Variations and ideas

- **Two-way channels.** Both parties sign each new pair of balances with a counter. Closing starts a waiting period (a clock guard) in which the other side can present a newer signed state.
- **A private channel.** Put the record and vault on a private PDA held by both parties through a group key. Capacity and totals are then hidden too. Private state is single-writer, so a party who keeps updating the account can make the other's prepared redemption fail, up to the expiry.
- **Routed payments.** A channel can hold an amount locked by a hash, as in the [hash time-locked transfer](escrow-auctions.md). The routing network is off-chain software and is not designed here.
- **Settling for a private recipient who is offline.** With the `Secret` gate above, only the recipient can redeem. A third gate, `Keys(npk, vpk)`, would let anyone redeem: `plan` derives the id of a fresh slot from those keys and requires the destination to be it. It still takes a privacy-preserving transaction, and it pins the recipient to a private placement, which pattern 17 advises against.
