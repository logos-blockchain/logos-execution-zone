# The privacy circuit

The circuit is a RISC Zero guest that replays a private transaction and emits the object the chain publishes. Every privacy claim in this guide is a claim about what that object contains.

Source: `lee/privacy_preserving_circuit/src/{main.rs,output.rs,private_backend.rs}`, with the published shapes in `lee/state_machine/core/src/circuit_io.rs`.

## What it receives

```rust
PrivacyPreservingCircuitInput {
    input,                      // ProvingInput: root, public context, witnesses, padding
    program_image_witnesses,
    shadow_program_witnesses,
    responses,
    sender_presentations,
    message_seals,
    predicted_cross_messages,
}
```

The root is a `TransactionEntry`: either a sync message the sender initiated, or an async message being consumed out of a mailbox, in which case the circuit also computes its spend.

## What it does

It runs the same execution engine the sequencer runs, with a backend that proves each handler invocation separately and refuses to read public state. `the_prover_never_reads_a_public_actor_state` asserts exactly that refusal. Then it verifies each inner receipt against the image id claimed for that account, composing them as assumptions rather than re-executing them, and `a_receipt_for_other_inputs_does_not_bind_in_the_circuit` asserts that a receipt produced for different inputs does not satisfy the composition.

Three checks are worth knowing because they close holes a dishonest prover would otherwise have.

Reserved accounts cannot claim guest bytecode. The native token program and the program loader run protocol code, and the circuit asserts that no image witness names either: "A reserved program account has no deployable bytecode to claim". Tested by `a_guest_image_claim_for_the_reserved_id_is_refused` and `a_private_call_into_the_program_loader_is_refused`.

An account cannot be claimed twice. If the same account id arrives as both a program-image claim and a shadow witness, the circuit panics.

Claims are minimal and complete. `only_the_programs_the_private_part_runs_are_claimed` asserts nothing extra is claimed, while `missing_responses_are_rejected_by_the_circuit` and `surplus_responses_are_rejected_by_the_circuit` assert the handler responses must match the execution exactly, neither short nor padded.

Undisclosed claims are checked rather than trusted. For a disclosed image the sequencer compares the claim against chain state at settlement. For an undisclosed one the circuit itself checks the header is immutable and derives the membership root.

Native token operations are recomputed from protocol code rather than proved, which is why a private transfer of native balance is cheap and discloses no program.

## What it publishes

`compute_circuit_output` builds the message. Two parts of `output.rs` matter to a reader of the privacy chapters.

`obfuscate_output_ordering` sorts the published actions so their order carries nothing. Nullifiers and commitments are sorted separately, which decouples them: you cannot tell which commitment replaced which nullifier.

`emit_dummy_output` fills the padding. The wallet pads every private transaction to seven private actions, so one real action and six are indistinguishable from any other combination, and the dummies are generated here. `note_ciphertext_is_padded_to_the_requested_length` asserts the length side of it.

Uniform length is what makes padding work, and it is tested per note kind: `every_sealed_note_under_its_floor_has_one_length` and `every_recovery_note_has_one_length`. A note whose size varied with its contents would leak through that size no matter how well it was encrypted.

Confidentiality and addressing are tested together, which is the right pairing: `a_sealed_message_opens_only_to_its_recipient_and_only_as_committed`, `a_seal_refuses_a_body_addressed_anywhere_but_its_recipient`, and `a_recovery_note_opens_to_its_recipient_only_under_its_viewing_secret_and_address`. Encryption alone is not the property that matters; a body that opened for the right key but the wrong recipient would still be a break.

## Why a prover cannot lie

The sequencer does not take the published journal on trust. It rebuilds the parts it can derive independently, the authorization bits from the signatures it actually received and every disclosed image claim from the program actually deployed at that account id, and verifies the proof against those bytes. A prover that claimed a different image, or claimed an account was authorized when no signature covered it, produces a proof that does not verify against the journal the sequencer reconstructs.

This is the mechanism behind a sentence that appears several times in Part III: the chain does not need to trust the prover about anything it can check for itself.

## How this chapter was checked

Every claim above corresponds to a named test, and the suite passes: 483 tests across `lee` and `lee_core`, all green, under `RISC0_DEV_MODE=1 cargo nextest run -p lee -p lee_core`. The circuit's own tests are in `lee/state_machine/src/privacy_preserving_transaction/circuit/tests.rs`, with the note and seal properties in `lee/state_machine/core/src/{sealing.rs,recovery.rs}`.

Note what dev mode does and does not buy. `RISC0_DEV_MODE=1` skips real proof generation, so these runs exercise the circuit's logic, its assertions and its output, but not the cryptographic soundness of the proofs themselves. The tests that do prove for real are the slow ones, and they are plain `#[test]` rather than feature-gated.

## Keeping this chapter honest

[What a private transaction reveals](../privacy/what-leaks.md) is written from the published object, field by field. If the circuit's output changes and that chapter does not, the guide starts lying about privacy, which is the worst failure mode available to it. The two should be reviewed together, and a change to `circuit_io.rs` is the signal to do it.
