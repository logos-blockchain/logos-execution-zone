# CACP demo

This command runs a presentation-oriented reference model for the locked demo
scope:

- one in-memory Bedrock model;
- two distinct zones, each with one sequencer key;
- one joint Mantle transaction containing exactly two `ChannelInscribe`
  operations;
- no bridge, token, ping, indexer, web UI, or ZK flow.

It is not a live Bedrock node or a pair of running sequencer services. The
binary exercises the real Mantle transaction and signature types through the
`cross_zone` CACP state machines and an in-memory atomic Bedrock model.

## Costly Abort boundary

Costly Abort is deliberately not implemented by this binary. Logos L1 channel
inscriptions carry data; they do not execute a vault, lock funds, or seize a
sequencer's stake. Including a stake amount in an inscription would therefore
be an unenforceable promise, not a penalty mechanism.

A real implementation requires an external execution layer with asset custody,
challenge/response rules, and authenticated receipts for deposit, release, and
forfeit operations. The current specifications leave the cross-layer proof
between that enforcer and Bedrock as an open integration question.

## Run

From the repository root:

```console
just demo-cacp
```

The command exits unsuccessfully if any stated invariant fails. A successful
run ends with:

```text
ALL 4 CACP SCENARIOS PASSED
```

## Expected scenarios

1. **Happy path:** A proposes, B accepts, A finalizes, and Bedrock includes one
   jointly signed transaction with two inscriptions.
2. **B fallback after Phase 3:** once both signatures exist, B can submit the
   same transaction if A stalls; a later duplicate submission is idempotent.
3. **Safe abort before Phase 3:** a timeout before both signatures exist leaves
   no submittable transaction and advances neither channel.
4. **Stale-parent rejection:** a stale parent on either inscription rejects the
   entire joint transaction, so neither channel tip changes.

For a live presentation, run the single command and read each `PASS` line as
the expected result for that scenario.
