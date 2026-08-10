# CACP + costly-abort live demo

This command boots a real local multi-process LEZ development network:

- one Bedrock Docker node;
- participant Zone A with its own sequencer and channel;
- participant Zone B with its own sequencer and channel;
- a third, neutral LEZ execution zone for the `cacp_bond` program;
- no bridge, application token, ping, indexer, web UI, or proof generation.

The joint Bedrock transaction has exactly two business operations, both
`ChannelInscribe`. Bedrock's wallet appends one `Transfer` operation to pay the
real transaction fee. The CACP implementation rejects every other shape.

## What changed from the reference model

The stakes now come from two funded LEZ public accounts. They are transferred
through sequencer JSON-RPC into a proposal-specific escrow PDA owned through
the `cacp_bond` program. Challenges, response deadlines, Ed25519 evidence and
payouts execute inside the neutral zone. There is no resolver/custodian private
key that can choose a winner or seize escrow.

The program verifies the signatures and commitments that identify which party
failed before Phase 3. After Phase 3, both parties possess the same fully signed
Bedrock transaction, so the protocol outcome is fallback submission rather
than abort. The demo checks actual Bedrock channel tips to confirm inclusion.

This is a real local devnet, not an externally hosted public testnet. It spends
only deterministic development funds created by the local fixtures.

## Run

Docker must be running. From the repository root:

```console
just demo-cacp
```

A successful run ends with:

```text
ALL 5 LIVE CACP SCENARIOS PASSED
```

## Scenarios

1. Happy path: A submits the jointly signed, fee-funded transaction and both
   participant channel tips advance.
2. Phase-3 fallback: A stalls; B submits the identical retained transaction.
3. Pre-Phase-3 safe abort: no fully signed transaction exists and neither tip
   advances.
4. Stale parent: A's parent advances first; Bedrock rejects the old joint
   transaction atomically, including B's otherwise-current inscription.
5. Costly abort: the neutral `cacp_bond` program executes both attributed
   cases—B withholds ACCEPT and A withholds FINALIZE—and transfers escrow to
   the honest public account after the challenge window expires.
