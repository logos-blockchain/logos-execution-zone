# What a private transaction reveals

"Private" in LEZ means: the values of private accounts and the plan that produced a transaction are hidden. It does not mean the transaction is invisible. This chapter walks through a private transaction as the chain sees it, field by field, and names what each field gives away. Read it with a specific design in mind and it becomes a checklist.

The published object is `PrivacyPreservingTransaction { message, witness_set }` (`lee/state_machine/src/privacy_preserving_transaction/`). Everything below is in it.

## Public actions

```rust
pub struct PublicActionWithID { account_id: AccountId, effects: Vec<DeferredPublicEffect> }
pub struct DeferredPublicEffect { program_account_id, shard_program_account_id, data: Vec<u8> }
```

One entry per **public account** the root call listed, in root order, whether or not anything happened to it. For each, the full list of effects aimed at it, in execution order, with the bytes of the effect.

What leaks:

- **Every public account touched**, by id. A deshielded transfer names the recipient. A private swap names the pool and both vaults.
- **Which program emitted each effect** (`program_account_id`) and which shard it targets. Even a program declared undisclosed is named here if it touches a public account.
- **The effect payload, in full.** For the native token that is `Credit(amount)` or `Debit(amount)`: the amount is public. For `token::Transfer` into a public holding it is `Deposit { descriptor, amount }`. For the AMM it is the whole `SwapBinding`: token program, both vaults, both definitions, `amount_in`, `amount_out`. For a clock guard it is the proposed timestamp or deadline. Design your `Effect` type knowing that anything aimed at a public shard is a public record.
- **Ordering** of effects within one account, and the relative order of accounts (root order, which the wallet decides).

What does not leak: which private account funded a credit, whether a listed public account was actually modified (a guard-only account shows an effect with `post_data` unknown to observers, but the effect bytes themselves still show), and the instruction data of the root call.

## Nonces and signatures

`message.nonces` and `witness_set.signatures_and_public_keys` list every **public account that authorized** the transaction, with its key and current nonce. A shielding transfer from a public account signs; the account is therefore linked to the transaction and to the nullifiers and commitments it carries. Whether that links it to a *private account* depends on what else the transaction shows: a public sender plus one non-dummy-looking `Init` is a strong hint that the sender funded that commitment.

A private-to-public transfer signs nothing (`deshielded_transfer_does_not_sign_with_recipient_key`), so the recipient is named but not linked by signature.

## Private actions

```rust
pub struct PrivateAction { nullifier, root, commitment, encrypted_post_state }
```

Always exactly `MAX_PRIVATE_ACCOUNTS` = 7 of them when the wallet builds the transaction (real ones plus dummies), sorted by nullifier bytes, commitments sorted separately.

What leaks:

- **Nothing about which account** a real action belongs to, for an `Update`: the nullifier is `H(commitment_pre ‖ nsk)` and the commitment is a fresh hash. Linking two updates of the same account requires `nsk`.
- **Something, for an `Init`.** The nullifier of an initialization is `H(account_id)`. Anyone who knows the account id (that is, `(npk, vpk, identifier)`) can recognize the moment it was initialized. A published donation key with a guessable identifier is watchable. Random identifiers, which the wallet uses by default, close this.
- **The root.** Each action names the commitment-set root its membership proof was built against (or an arbitrary known root for `Init`). A stale root says "this note is older than that root". Wallets should prove against recent roots.
- **The view tag**, one byte, is key-derived as `H(npk ‖ vpk)[0]` on an **init note only**; an update note carries a random byte and is found by nullifier instead. Two init notes with the same tag are 256 times more likely than chance to belong to the same key. Across a long history that is a usable correlation signal against a low-traffic key. It is a deliberate trade for sync speed.
- **The note length.** Notes are padded to 512 bytes by the wallet. An account whose encoded state (all shards) exceeds that ships a longer note and stands out; the wallet warns. A design that stores a large blob in a private shard should expect its notes to be recognizable by size, up to the 8 KiB protocol maximum pad.
- **The count**, up to 7. A transaction with more than seven private accounts cannot be padded and reveals its exact count.

What does not leak: values, shard contents, which program's shards changed, whether the account is a PDA or regular (the note header is inside the ciphertext and the header is fixed-width).

## Validity windows

`block_validity_window` and `timestamp_validity_window` are in the clear. A tight window says when the transaction was meant to land; an unusual one is a fingerprint of the wallet or program that set it. Programs that set windows for expiry should use coarse, common values.

## Program image claims

`program_image_claims` lists, for every **disclosed** program in the prover's dependency map (invoked or not), its account id and image id; for every undisclosed one, a commitment root; and nothing for shadow programs or native token calls. The chain learns "this transaction involved the token program and the AMM" from the claims alone, even when every account touched is private.

Deferred public effects name their program independently, so an undisclosed program with any public footprint is disclosed anyway.

## Proof

The proof is a succinct STARK receipt of the privacy circuit. It reveals nothing beyond its journal, which is the message above. Its size is fixed (`PROOF_BYTES`), so it carries no information about the computation's shape.

## What is not published at all

- The root call's program and instruction data.
- The `PlanInput` and `PlanOutput` of any call, and all guest receipts. Only the circuit's journal is published.
- Chained call structure: which programs called which, with what selectors, in what order.
- Events. They are dropped.
- Any private account's id, value, kind or shards.
- Which private accounts were `Init` versus `Update` (except through the deterministic init nullifier, if the observer already knows the account id).

## Metadata outside the message

- **Submission.** The sequencer you submit to sees your IP and the time. Proving takes minutes, so the timestamp of submission is not the timestamp of intent.
- **Timing correlation.** A public credit that lands a block after a private debit of the same size is a correlation, not a proof, but it is the kind of thing chain analysis is built on. Round amounts and prompt spending both help an observer.
- **Mempool.** Before inclusion the transaction is gossiped between sequencers in full.
- **The wallet's sync queries.** `sync-private` fetches private actions from a node; which blocks a wallet asks for can hint at when it last synced.

## A worked example: private swap against a public pool

Trader holds token A in a private account, receives token B into another private account, swaps through the public AMM pool. The chain sees:

| Field | Content | Leak |
|---|---|---|
| public actions | pool: `Swap(SwapBinding{…amount_in: 100, amount_out: 75…})`; vault A: `Deposit{A, 100}`; vault B: `Withdraw{B, 75}` | the trade, fully: pair, direction, size, price |
| signatures | none | nothing |
| private actions | 7, two real (`Update` of the A note, `Init` of the B note) | nothing linkable |
| claims | AMM disclosed, token disclosed | that it was an AMM swap (already obvious) |
| windows | unbounded | nothing |

Conclusion: a private swap hides *who* traded, not *what* was traded. The catalog's [AMM chapter](../catalog/amm.md) discusses what can and cannot be done about that.

## A second example: private donation to a published key

Donor's private account, `Init` of a fresh account under the charity's key with a random identifier, native transfer. The chain sees seven private actions and nothing else: no public actions, no signatures, no claims (native transfers make none). Two dummy-looking `Init`s among seven actions. This is as private as LEZ gets; the [donations chapter](../catalog/donations.md) builds on it.
