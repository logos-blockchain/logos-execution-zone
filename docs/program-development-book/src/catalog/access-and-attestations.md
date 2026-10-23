# Tickets, attestations and registries

Small programs that turn "I hold something" into "I am allowed to do something", plus the registries that make holding possible.

## Tickets: prove you hold, without showing what

A venue issues tickets as NFT printed copies (the token program) into buyers' private accounts. At the door the holder must prove they hold a ticket to this event, once.

| Account | Placement |
|---|---|
| Ticket holding | token program's shard on the holder's private account |
| Admission board | public PDA of the door program `H("event", id)` |
| Admission receipt | public PDA `H("admit", id, nullifier)` |

The holder's private transaction lists their private holding (unauthorized is enough: the program only inspects it), the board and a receipt:

```rust
Instruction::Admit { event_id, secret: [u8;32], definition_id }
// plan:
plan.inspect(holding, token_program_id, &Guard::HoldsPrintedCopy { definition_id });
let nullifier = sha256(&(b"admit", event_id, secret));       // secret: any per-holder value
plan.effect(board, &Effect::Admitted);                       // counter += 1
plan.effect(receipt, &Effect::Once);                         // refuse if non-empty
// apply on the holding (private, in the proof):
Guard::HoldsPrintedCopy { definition_id } => {
    let h = TokenHolding::try_from(pre_data)?;
    assert!(matches!(h, TokenHolding::NftPrintedCopy { definition_id: d, owned: true } if d == definition_id));
    None
}
```

The inspect on the private holding runs in the proof: the chain never sees the holding, only that the proof required one. The public effects say "one more admission" and burn a receipt that no *stranger* can link to a ticket.

**The venue can link it, and the venue is the party this design exists to hide attendance from.** Binding the receipt to the holding, below, makes its address a deterministic function of `holding_account_id`. Under the issuance in this chapter the venue names each buyer's private account to write the holding onto it, so it holds the whole preimage set. That is a property of this issuance, not of the protocol: a bearer voucher the buyer redeems themselves never shows the venue an account id, and its receipt is then unlinkable to the venue too. It can compute every receipt address and read off exactly which tickets were used. Hashing is not concealment when the preimage set is known and small, which is the rule stated in [What a private transaction reveals](../privacy/what-leaks.md).

The tension is real and the chapter cannot have both: an unlinkable receipt and one-admission-per-ticket are not simultaneously available here. With a random per-holder `secret` the receipt is unlinkable and one ticket admits many people. With the binding below, admission is capped and the issuer can enumerate. This chapter takes the capped one: the receipt nullifier is `H(event ‖ holding_account_id)`, and the plan knows `holding.account_id` from `AccountMeta`. That binds one admission per ticket-holding account. Read the receipt as unlinkable to the public and linkable by whoever knows the holding account ids, which for venue-issued tickets is the venue.

Transferable tickets stay transferable: the token program moves them privately between accounts, and the receipt is per holding account, so a resold ticket admits its new holder if the previous one never used it.

{{#include ../diagrams/attestations-ticket.svg}}

## Attestations: prove a fact about your private state

Generalizing the ticket: any program can let a holder emit a public statement whose truth is checked against a **private** shard inside the proof.

```rust
// generic "attest" instruction in a program that owns a private record
Instruction::Attest { claim: Claim }
plan.effect(private_record, &Effect::Satisfies(claim.clone()));  // guard in the proof
plan.effect(public_target, &Effect::Attested(claim));            // public statement
```

Examples: "my donation receipt for campaign C is at least X" ([donations](donations.md)), "my private balance of token T is at least N" (inspect on the holder's own token shard), "I completed level 10" ([LeZork](lezork.md)), "I am over the age in this credential" (a credential issued into a private PDA by an issuer, see below).

The statement is exactly as strong as the program that emits it: the verifier of `Attested(claim)` must trust that the emitting program's `plan` only emits it behind the right guard, and must pin the program (`caller_account_id` if chained, or the effect's `program_account_id` in the public action). Because the emitting program is disclosed by its claim or its public effect, the verifier can check which one it was.

## Credentials issued into private accounts

An issuer (a KYC provider, a DAO, a game) hands a holder a credential by **initializing a private PDA** of the issuer's program under the holder's key:

```rust
let slot = AccountId::for_private_pda(&issuer_program, &H("cred", kind), &holder_npk, &holder_vpk, identifier);
plan.effect(slot_meta, &Effect::Issue(Credential { kind, expires_ms, .. }));   // write_once
```

The holder's wallet discovers it on sync. Only the holder can see it; only the issuer program can authorize changes to it (revocation would be an `Update`, which needs the holder's `nsk`, so **the issuer cannot revoke a credential it has issued**; expiry must be in the credential and checked by the clock guard at use). This asymmetry, "issued once, then the holder's", is a feature for self-sovereign credentials and a limitation for revocable ones. Revocation lists must be public: a registry of revoked commitments the attestation guard checks with a Merkle non-membership proof, or a public per-credential PDA the issuer can write.

## Registries with write-once claims

A name registry, a DNS, a package index: entries are public PDAs seeded by the name, written once, owned by whoever claims first.

```rust
Instruction::Claim { name: Vec<u8>, owner: Owner }     // Owner::Account(id) | Owner::Secret(H(s))
let entry = AccountId::for_public_pda(&me, &PdaSeed::new(sha256(&name)));
plan.effect(entry_meta, &Effect::Claim(owner));         // apply: write_once
Instruction::Update { name, value, secret: Option<..> } // owner check: signature or secret
```

A **private owner** (secret credential) updates their entry through private transactions; the chain sees the entry change and nothing about the owner. Front-running of claims is a sequencer-ordering matter; commit-reveal fixes it (claim `H(name ‖ salt)` first, reveal later) at the cost of two transactions.

## Airdrops and one-time claims

A public Merkle root of eligible leaves; a claimant proves a leaf in instruction data; a receipt PDA per leaf nullifier prevents double claims; the payout goes to a fresh private slot.

- Leaf `H(secret)`: fully anonymous claims. The issuer must have distributed secrets, off chain.
- Leaf `H(public_account_id)`: claimant must sign, so claims are public. Simpler distribution.
- Private receipts instead of public ones: the receipt is a private PDA of the airdrop program under the claimant's key with **identifier pinned to `Identifier::ZERO`** (the instruction carries `npk` and `vpk`, the plan recomputes `for_private_pda(.., Identifier::ZERO)` and requires the listed account to be it). Since a private account initializes at most once, the second claim's `Init` is refused by the nullifier set. That is a one-per-key rule with no public receipt at all. This is one of the few legitimate address derivations in a plan: the point of the derivation is exactly to pin the *identifier*, and the keys it needs travel in private instruction data.

## Interoperability matrix

| Design | Holder/claimant | Verifier sees | Hidden |
|---|---|---|---|
| Ticket admission | private holding | one admission, a receipt the public cannot link and the issuer can | which ticket, who |
| Attestation | private record | the claim, the emitting program | everything else about the record |
| Credential issue | private PDA | nothing (if issuer private) or the issuer's signature | the holder, the contents |
| Name registry, secret owner | private tx | entry changes | the owner |
| Airdrop, private receipts | private tx | a credit to a fresh slot | who claimed |

## Ideas

- **Proof of reserves for a private treasury**: a treasury program's `Attest { at_least }` over a private vault PDA. Public, verifiable, without a balance.
- **Selective disclosure of a credential's fields**: the guard checks only the field the claim names; the rest stays in the note.
- **Reputation**: an issuer program adds points to a holder's private PDA (needs the holder's transaction, since only they can update: the holder submits `Claim { points_proof }` where the proof is a signed statement from the issuer carried in instruction data and checked in the plan against a public issuer key). Signature verification in the guest costs cycles; ed25519 is what `sequencer_stake` uses.
- **What does not work:** issuer-side revocation of a private credential (no `nsk`); reading a holder's credential without the holder's transaction; a registry entry that is both private and claimable by first-come (the claim must be public to be ordered).
