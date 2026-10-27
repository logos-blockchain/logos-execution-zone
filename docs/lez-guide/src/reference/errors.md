# Errors

Two error types matter to a reader. `ExecutionError` comes from the engine while a transaction executes. `LeeError` is everything else: proving, validation, serialization, settlement.

Sources: `lee/state_machine/core/src/execution_state.rs` and `lee/state_machine/src/error.rs`.

## The ones you will actually hit

| Error | What happened |
|---|---|
| `ProgramExecutionFailed("Guest panicked: <msg>")` | your handler's assertion failed, and `<msg>` is yours. Write assertions that name the check |
| `UndeclaredActor` | a `SyncMessage` to an actor the transaction did not declare and so cannot run |
| `UnboundAsyncDestination` | an `AsyncMessage` **from a public actor** to an address with no recovery binding on chain and none introduced by the same transaction, so it cannot be stored |
| `UnadmittedPublicActor` | a public actor the transaction touched without admitting it |
| `MissingFeeDeclaration` | a user public transaction built with the fee-exempt `try_new` instead of `try_new_with_fees` |
| `OutOfGas` | the transaction exceeded its declared `gas_limit` |
| `OutOfValidityWindow` | the block or timestamp fell outside the window the handler set |
| `UnknownProgram` | a deferred public effect naming a program the sequencer cannot load, which is what a shadow program's public effect does |
| `MaxAccountNonceReached` | an account's nonce is exhausted |
| `InvalidPrivacyPreservingProof` | the proof did not verify against the journal the sequencer rebuilt, which is what a prover that lied produces |

## Engine errors in full

`PublicActorStateUnavailable`, `DuplicateWitness`, `FamilyBindingConflict`, `PublicFamilyMemberDeclared`, `AliasCollision`, `MissingSenderPresentation`, `LoaderOutsidePublicExecution`, `UndeclaredActor`, `UnadmittedPublicActor`, `UnreachedPromotion`, `TransitionInputMismatch`, `EmptyValidityWindowIntersection`, `PublicAndPrivate`, `MissingPredictedCrossMessages`, `UnusedPredictedCrossMessages`, `UndeclaredCrossMessageSender`, `BoundaryMismatch`, `CrossMessageMismatch`, `IncompleteBoundary`.

Several are about the boundary between public and private execution, and they mean the prover and the sequencer disagree about what crossed it. A client building transactions by hand rather than through the wallet is the usual cause.

`PublicActorStateUnavailable` is not a bug. Inside a proof, a public account's actor state is unreadable by construction, so any attempt to read one surfaces as this. The design answer is to assert against the public state at settlement rather than read it while proving ([What you cannot do privately](../privacy/limits.md)).

## `LeeError` in full

`InvalidInput`, `OutOfGas`, `InvalidProgramBehavior`, `MessageSerializationError`, `InvalidPrivateKey`, `Io`, `InvalidPublicKey`, `InvalidHexPublicKey`, `ProgramWriteInputFailed`, `ProgramExecutionFailed`, `ProgramExitedWithCode`, `ProgramProveFailed`, `TransactionDeserializationError`, `Core`, `CircuitOutputDeserializationError`, `InvalidPrivacyPreservingProof`, `CircuitProvingError`, `InvalidProgramBytecode`, `ProgramAlreadyExists`, `MaxAccountNonceReached`, `OutOfValidityWindow`, `UnknownProgram`, `UnboundAsyncDestination`.

## Tooling errors

`SegmentCountMismatch { expected, actual }` from a deploy whose `--segments` count does not match the chunk count. It reports the number expected, so the fix is mechanical. A deploy that fails partway cannot currently be resumed over the same accounts.

## Where an error surfaces

This is the single most useful debugging fact in the guide, and it depends on where the handler ran.

For a public transaction the handler runs on the sequencer, so a panic appears in the sequencer's log:

```
[WARN sequencer_core] Error at transition ProgramExecutionFailed(
        "Guest panicked: Missing required authorization",
    )
```

For a private transaction the handler runs on your machine, so the same panic comes back as a local error from the prover, before anything is submitted. That is the faster loop, and it is why developing against a private account with `RISC0_DEV_MODE=1` is often quicker than against a public one.

A refused private transaction is simply not included. Nothing changed, nothing was charged, and it can be resubmitted.
