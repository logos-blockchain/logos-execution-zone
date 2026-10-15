# Program identity: disclosed, undisclosed, shadow

A public transaction names its program in the clear and the sequencer loads the bytecode from chain state. A private transaction carries proofs, and a proof is verified against an image id, so the circuit needs to know which image id stands behind each account id the execution dispatched to. There are three ways to supply that, with three different privacy outcomes.

Source: `ProgramImageWitness` in `lee/state_machine/core/src/circuit_io.rs`; `ProgramWithDependencies` in `lee/state_machine/src/privacy_preserving_transaction/circuit/mod.rs`.

## Disclosed

```rust
ProgramWithDependencies::new(program, program_account_id, dependencies)
```

The default. The prover states "account `A` runs image `I`", the circuit trusts that for verification, and the message carries `ProgramImageClaim::Disclosed { account_id, image_id }`. At settlement the sequencer looks up the real image id deployed at `A` and rebuilds the claim from that; if the prover's `I` was wrong, the reconstructed journal differs and the proof fails.

What the chain learns: the account id and image id of **every program in the dependency map**, whether or not it was invoked. A private token transfer discloses that the token program ran. A private AMM swap discloses the AMM and the token program.

## Undisclosed

```rust
.as_undisclosed_program(program_header, membership_proof)
.with_undisclosed_dependency(account_id, program_header, membership_proof)
```

Available only for a program whose header is **immutable**. When a header becomes immutable, the loader adds `immutable_mirror_commitment(header_id, header)` to the commitment set. An undisclosed witness carries the header and a Merkle proof of that mirror; the circuit checks `header.immutable`, recomputes the root, and the message carries only `ProgramImageClaim::Undisclosed { root }`. The sequencer checks the root is one the commitment tree has had.

What the chain learns: that *some* immutable program with a mirror under that root was involved. Not which one.

Caveats:

- Any effect the program emits on a **public** account is a `DeferredPublicEffect` that names `program_account_id` in the clear, because the sequencer must load that program to apply it. Undisclosed identity survives only for programs whose public footprint in the transaction is empty. An undisclosed program can chain into disclosed ones, but then those are disclosed.
- The membership proof is against a specific historical root; wallets should use a recent one, or the root itself narrows down when the program was deployed.
- The program still has to be deployed. Undisclosed hides which deployed program ran, not that it exists.

## Shadow

```rust
ProgramWithDependencies::new(program, self_account_id, HashMap::new())
    .as_shadow_program()
    .with_shadow_dependency(account_id)
```

A shadow program is **never deployed**. It is dispatched at `AccountId::for_shadow_program(&image_id)`, the circuit takes its image id from a `ShadowProgramWitness`, verifies its receipts like any other, and emits **no claim at all**. The sequencer never hears of it.

What the chain learns: nothing about the program.

The price: a shadow program can only ever act on **private accounts**. It has no header on chain, so a deferred public effect naming its shadow address fails at settlement with `UnknownProgram` (test `a_shadow_programs_public_effect_is_refused_at_settlement`). It may own private shards and private PDAs (`shadow_program_claims_a_private_pda_it_legitimately_owns`) and it may chain into deployed programs, which then appear as disclosed or undisclosed claims and may touch public state on its behalf.

Shadow programs are the closest thing LEZ has to "private smart contracts": logic that exists only on the machines of the people who use it, enforcing invariants over private state that the chain sees only as commitments. A private ledger between two parties, a private game, a private accounting rule. The chain guarantees that whatever state those parties hold evolves according to that bytecode, and learns nothing else.

Because a shadow address is derived from the image id alone, everyone running the same bytecode shares one dispatch address and one family of PDAs. Two users of the same shadow program do not interfere: their private PDAs differ by `(npk, vpk, identifier)`.

## Summary

| | Deployed | Claim in message | Public effects | Reveals |
|---|---|---|---|---|
| Disclosed | yes | `Disclosed { account, image }` | allowed | which program, always |
| Undisclosed | yes, immutable | `Undisclosed { root }` | allowed but disclose the program | only a commitment root, if no public effects |
| Shadow | no | none | refused at settlement | nothing |

Native token calls are recomputed by the circuit from protocol code; they carry no claim and no receipt, and a private transaction that only moves native balance discloses no program at all. The program loader cannot run privately in any mode.
