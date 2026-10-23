# The input echo: why a handler's proof binds to its input

## The problem

A zero-knowledge receipt proves that some program ran and produced some output. By itself it says nothing about what the program was given. A handler proven on a made-up balance, a made-up sender or a made-up `is_authorized` flag produces a perfectly valid receipt.

In the public case this does not matter: the sequencer runs the handler itself and supplies the real input. In the private case the handler runs on the user's machine, and the user chooses the input.

## The fix

The output of a handler run is not the `Response` alone. It is a `Transition`, which carries the input next to the response (`lee/state_machine/core/src/program/mod.rs`):

```rust
pub struct Transition {
    pub input: ReceiveInput,
    pub response: Response,
}
```

The guest commits the whole `Transition` to its journal. The program author does nothing: `actor_entrypoint!` reads the input, lends it to the handler, and commits it back unchanged next to the handler's response. Only a guest that writes its own `main` has to take care to commit the input it was given.

What must match, byte for byte, is the whole `ReceiveInput`: the receiver, the sender, the authorization flag, the starting state and the message. It is checked in two places.

**On the sequencer**, for a public actor. The sequencer runs the guest, decodes the `Transition` it committed, and the engine compares (`process_actor_message`, `lee/state_machine/core/src/execution_state.rs`):

```rust
let transition = environment.handle_message(&input, &view)?;
if transition.input != input {
    return Err(ExecutionError::TransitionInputMismatch { .. });
}
```

**In the privacy circuit**, for a private actor. The prover hands the circuit only the handler's **response**. The circuit attaches the input the engine itself computed, and requires a receipt for exactly those bytes (`lee/privacy_preserving_circuit/src/private_backend.rs`):

```rust
let transition = response.into_transition(input.clone());
env::verify(image_id, &lee_core::to_borsh_frame(&transition));
```

A receipt made by running the handler on any other input committed different bytes, so it does not verify.

So the proof of a private transaction says: this exact program, given this exact receiver, sender, authorization flag, starting state and message, produced this exact response.

## What this buys

- **The starting state is real.** The circuit separately proves that the private account's state is the one committed on chain. The echo ties the handler run to that state.
- **The sender is real.** `from` is supplied by the engine from the message being delivered. A program cannot be shown a sender that did not send.
- **Authorization is real.** `is_authorized` is computed by the engine, and the handler ran with that value.
- **Private output can be trusted in public.** A message leaving a private actor was produced by the proven handler from proven input. This is the property behind the [proof-carrying message](../patterns/index.md) pattern, which most of the catalog uses.

## What the echo assumes

The echo is written by the guest. Nothing outside the guest can force it to be honest: a zkVM receipt binds a program to its journal, not to what the host fed it. A program with a hand-written `main` could read one input, compute a response from it, and commit a different input next to that response.

So the guarantee is conditional: **for a program whose code echoes faithfully, a prover cannot feed it a false input.** Programs built with `actor_entrypoint!` echo faithfully by construction, and a deployed program cannot be swapped, because the proof names its image.

A program that lies in its echo gains nothing beyond what any dishonest program already has.

- **In a public transaction it simply fails.** The sequencer supplied the real input, the committed one differs, and the engine rejects the transition.
- **In a private transaction it lets its own prover produce any response.** That is the same as a program with an instruction "do whatever the caller says". The response can still only write the state of that program's own actor and send messages that carry that program's name as sender.

The echo protects everyone who relies on an honest program from dishonest provers. It does not protect anyone from a dishonest program. Relying on a message from an actor means trusting that actor's program, and "it uses the standard entry point" is one line of that review.

## What it does not hide

The echo is inside the proof. It is not published. An observer of a private transaction does not see the input or the response of a private handler. They see only what crosses to the public side, which is listed in [What a private transaction reveals](../privacy/what-leaks.md).

## A short rule

A handler never needs to re-check that its input is genuine. It needs to check that the input is **acceptable**: the right sender, the right authorization, a valid state transition.
