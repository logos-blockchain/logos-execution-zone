# Sources

The book was written from the code of pull request 935, "transactional actors with side-effects", at commit `faaa07251`. Nothing in it was run.

## In the repository

| Topic | File |
|---|---|
| Handler interface, messages, responses, validity windows, account-id derivations | `lee/state_machine/core/src/program/mod.rs` |
| Accounts, actors | `lee/state_machine/core/src/account.rs` |
| The execution engine: delivery, authorization, the boundary | `lee/state_machine/core/src/execution_state.rs` |
| Native token | `lee/state_machine/core/src/native_token.rs` |
| Private witnesses, the public fields of a private transaction | `lee/state_machine/core/src/circuit_io.rs` |
| Recovery bindings, sealed messages | `lee/state_machine/core/src/recovery.rs`, `sealing.rs` |
| The privacy circuit | `lee/privacy_preserving_circuit/src/` |
| Settlement, admission, publication of async messages | `lee/state_machine/src/validated_state_diff/` |
| Group keys | `lee/key_protocol/src/key_management/group_key_holder.rs` |
| Shipped programs | `lez/programs/` (token, clock, fee, bridge, sequencer stake, AMM and others) |
| Block rules for system transactions | `lez/chain_state/src/apply.rs`, `lez/common/src/transaction.rs` |
| Wallet: sending, collecting, groups | `lez/wallet/src/` |
| Worked example and tutorial | `examples/program_deployment/` |

## Outside the repository

- `logos-co/logos-lez-rln` on GitHub: the Logos RLN membership registry, a plan/apply program. The [RLN entry](../catalog/rln.md) is a toy version of it. Read: its README, instruction set, effect types and registration logic. Not read: its Merkle program in full, and the off-chain modules that make and verify the proofs.

## What was not examined

- The AMM and the associated-token-account program under the actor model.
- Cross-zone messaging.
- Shadow programs.
- The wallet's handling of blinded addresses, beyond the engine's support for them.
- Proving times. Proof counts in the book come from the engine's structure, not from measurement.

## Where this guide came from

This guide unifies two earlier books. One documented the actor interface against pull request 935 before it merged; its chapters form Part III here, and it has been removed rather than kept, so there is only ever one copy of that material. The other documented the plan/apply interface, and it is kept at `docs/program-development-book/` because plan/apply is what every current release runs. [Which interface you are writing for](../understand/which-interface.md) says which applies to you.

Both were written before 935 merged, so the names they predicted have been brought in line with the code that shipped: `Call` is `SyncMessage`, `Cast` is `AsyncMessage`, `Response::call` and `Response::cast` are `send_sync` and `send_async`, `define_actor_logic!` is `actor_entrypoint!`, `WholeTransaction` is `WholeExecution`, and `Scope` is `Mode`.
