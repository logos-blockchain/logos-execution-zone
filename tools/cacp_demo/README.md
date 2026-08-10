# CACP demo

This command runs a presentation-oriented reference model for the locked demo
scope:

- one in-memory Bedrock model;
- two distinct zones, each with one sequencer key;
- one joint Mantle transaction containing exactly two `ChannelInscribe`
  operations;
- no bridge, application token, ping, indexer, web UI, or ZK flow;
- one external LEZ custody step using existing native public-account balances,
  `authenticated_transfer`, and `vault`.

It is not a live Bedrock node or a pair of running sequencer services. The
binary exercises the real Mantle transaction and signature types through the
`cross_zone` CACP state machines and an in-memory atomic Bedrock model.

## Real token commitment and its boundary

The fifth scenario executes real LEZ public transactions. Each sequencer signs
a transfer from its funded public account into a vault PDA controlled by an
external resolver. LEZ execution decreases both public balances, increases the
vault balance, rejects a claim signed by a sequencer instead of the resolver,
and finally transfers the forfeited stake to the honest counterparty.

This does not make the inscriptions executable. The CACP intent commits to the
external enforcer account and stake amount, while custody and settlement are
separate LEE transactions. The demo's resolver is explicitly trusted to map an
abort to the correct payout. Replacing that trust with on-chain challenge rules
and authenticated Bedrock-inclusion evidence remains an integration task.

## Run

From the repository root:

```console
just demo-cacp
```

The command exits unsuccessfully if any stated invariant fails. A successful
run ends with:

```text
ALL 5 CACP SCENARIOS PASSED
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
5. **Real public-account forfeiture:** A and B each deposit 1,000 native units
   through the LEZ vault program. A cannot reclaim the resolver's PDA. After an
   externally attributed abort by A, B receives both deposits, leaving A down
   1,000 and B up 1,000.

For a live presentation, run the single command and read each `PASS` line as
the expected result for that scenario.
