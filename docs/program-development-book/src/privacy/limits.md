# What you cannot do privately

The privacy model has hard edges. Some are consequences of the plan/apply design, some of the note model, some of the current implementation. This chapter lists them so a design does not discover them halfway through. Each item says whether it is structural (would need a protocol change) or current (an implementation choice that may change).

## Reading

**You cannot read another party's private account.** Structural. A private account's value exists only in its owner's notes. There is no way for a program, a transaction or a sequencer to read it. "Prove that Alice's private balance exceeds X" is impossible unless Alice herself makes the transaction.

**A plan cannot read anything.** Structural to the model. `plan` sees account ids, authorization bits and the instruction. Every state-dependent decision is a proposal in the instruction plus a guard in `apply`. There is no "read balance, then decide"; there is "claim balance is B, prove it, then decide as if B". For public state in a private transaction the guard runs at settlement, so the claim must still hold then.

**A private transaction cannot read public state at proving time.** Structural. Inside the circuit a public shard is unavailable. You can constrain it (a guard that fails at settlement if it does not hold) but not branch on it. A program that needs to compute from live public state (a market price, a counter) can only do so in a public transaction.

**Apply sees one shard.** Structural. An `apply` cannot compare two accounts, sum two balances or check a config while writing a record. Every cross-shard invariant is enforced by two applies that each check the caller's proposal against their own shard; the proposal is the join.

## Writing

**You cannot send to an initialized private account you do not control.** Structural. Updating a private account needs its `nsk`, its plaintext and a membership proof. A stranger has none. Receiving therefore always means **initializing a fresh account** under the recipient's key, which is why identifiers exist and why the wallet picks a random one per payment. A private account is a one-shot mailbox: written once by anyone, thereafter only by its owner, or by a party the owner has given a [deposit key](../foundations/private-accounts.md#deposit-keys-sharing-nsk-and-vsk-without-ask) (`nsk` and viewing seed, no `ask`), who can then credit it but not spend from it.

Consequences: a private "balance" is really a set of notes; sweeping them into one is the owner's job; a program cannot "credit Alice's private account" in the abstract, only "create a new private account of Alice's holding this".

**Shared private state is single-writer.** Structural. Two transactions that update the same private account spend the same nullifier; the second is refused. A group holding one private account through a group key can take turns, not act concurrently. Public state has no such limit because deferred effects commute at settlement.

**Public effects run in the clear.** Structural. Anything a private transaction does to a public account is a `DeferredPublicEffect` applied by the sequencer with its bytes on chain. A private transaction can move value into public accounts and gate itself on public state, but the *what* of both is public.

**A shadow program cannot touch public state.** Structural. Shadow programs are never deployed, so settlement cannot load them. Their reach is private accounts and chained calls into deployed programs.

**Undisclosed programs disclose themselves through public effects.** Structural. The effect names the program.

**The program loader cannot run privately.** Current. Deployment is a public, charged transaction.

## Counting and sizing

**At most seven private accounts per transaction, or the count leaks.** Current (wallet constant `MAX_PRIVATE_ACCOUNTS`). The circuit itself accepts any number; padding hides only up to seven.

**Notes are padded to 512 bytes, at most 8 KiB.** Current (wallet constant; protocol `MAX_CIPHERTEXT_PADDING`). Private accounts with large shards are recognizable by note length. Keep private shards small, or accept the fingerprint.

**Root call plus ten chained calls.** Structural (`MAX_NUMBER_CHAINED_CALLS`). Deep composition needs flattening.

**Shards are at most 100 KiB.** Structural. Private accounts are further bounded by the note pad if they want uniform notes.

## Identity and linkability

**Init nullifiers are deterministic.** Structural. `H(account_id)`. Anyone who knows an account id sees its initialization. Random identifiers make ids unguessable; predictable ones (a public counter, a username hash) make every payment to them watchable. This is the difference between a private donation and a public one that happens to be encrypted.

**Public co-signers are linked.** Structural. A public account that authorizes a private transaction signs it and appears in the witness set with its nonce.

**View tags correlate init notes to keys, weakly.** Current design choice. One byte, key-derived on init only; random on update.

**Program claims disclose the programs.** Structural for disclosed and for anything with public effects; avoidable only by undisclosed (no public effects, immutable header) or shadow (no public effects, no deployment).

**Amounts crossing the public boundary are visible.** Structural. Shielding and deshielding show the amount on the public side.

## Time and events

**Time is a guard, evaluated at settlement.** Structural. A private transaction proposes a timestamp; the sequencer checks the clock when it applies the transaction, and the proposed value is public. You can build "not before T" and "not after T" (validity windows), and "the clock said T when this settled". You cannot compute with the current time inside the proof.

**Events are dropped.** Current. A private execution cannot emit events. Notify through a shard write, which is a public effect if the target is public.

**No timers, no callbacks.** Structural. Nothing runs unless a transaction invokes it. "At time T, release the funds" needs someone to submit a transaction at T; the program can only refuse to act before T.

## Economics

**Private transactions are fee-exempt today.** Current, and marked as interim in `classify.rs`. This is a denial-of-service surface the protocol accepts for now, and it also means there is no private fee payer to design around yet. When private fees arrive, a payer will have to be named, which will create a new linkage to think about.

**A refused private transaction costs nothing on chain.** Current. Good for prepared offers, bad for spam analysis. Proving cost is the only rate limit.

**Proving is slow.** Current. Tens of seconds to minutes per transaction on a laptop. Designs that need many private transactions per user per minute do not fit.

## Composition

**Every program in a private call graph must be supplied to the prover.** Structural. The wallet needs the bytecode of every dependency, keyed by deployed account id. There is no on-chain resolution in the proof.

**A private transaction cannot deploy and call in one step.** Current (loader is public-only).

**Cross-zone messages are public.** Structural for the current design: the inbox is a sequencer-injected public transaction over the peer's public chain.

## No randomness, no oracles

**There is no randomness.** Structural. No block hash access, no VRF. Lotteries and fair ordering need commit-reveal over private accounts (which the model supports well) or an external beacon written into a public shard by a trusted party.

**There is no oracle.** Structural. External prices, results or identities enter only as shard writes by some account, whose trust is the program's problem.

## What is fine

To balance the list: a private transaction *can* move native tokens and custom tokens between any mix of accounts, run any program over private accounts with full logic, chain up to ten calls, gate on the clock and on public state through guards, be prepared long before submission, hold value in program-controlled private PDAs, be authorized by a program-derived grant with no key at all, and disclose nothing about which program ran when the program is shadow. The catalog is about using that set well.
