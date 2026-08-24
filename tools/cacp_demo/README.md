# CACP + costly-escalation live demo

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

The stakes come from two funded LEZ public accounts. They are transferred
through sequencer JSON-RPC into a proposal-specific escrow PDA owned through
the `cacp_bond` program. Challenges, response deadlines, Ed25519 evidence and
payouts execute inside the neutral zone. There is no resolver/custodian private
key that can choose a winner or seize escrow.

The intent also commits a neutral-zone fee collector plus fixed challenge and
response fees. A challenger pays the challenge fee directly to that collector;
a challenged participant pays the response fee when publishing a valid
response. Neither fee enters participant escrow or is paid to the other party.
The collector represents the neutral sequencer's normal conflict-resolution
execution revenue in this local network.

The bond is challenge-driven. A normal successful exchange needs no routine
on-chain confirmation: either party can close the bond by presenting both
signatures. Before staking, A commits to versioned canonical bytes containing
the exact funded Mantle transaction and its fee proof; B confirms the same
commitment when joining. If A says B withheld ACCEPT, A pays the challenge fee
and B must publish both those committed candidate bytes and its pre-committed
signature. If B says A withheld FINALIZE, B must publish the same complete
candidate and signature in the challenge. The chain data therefore gives A
everything needed to reconstruct FINALIZE instead of proving only that B once
signed an unavailable transaction.

A frivolous challenge costs the challenger a fixed fee and earns it nothing.
Answering on-chain also costs the responder a fixed fee and earns it nothing.
An unchallenged quiet-window timeout refunds both stakes; forfeiture is
possible only after an unanswered on-chain challenge. Like other optimistic
protocols, this requires participants or a watchtower to monitor the neutral
zone during the configured response window.

The program deliberately judges signature availability, not Bedrock inclusion:
the neutral execution zone cannot inspect another service's private mempool or
prove that a party received an off-chain packet. After Phase 3, both parties
possess the exact same fully signed Bedrock transaction (including the original
fee proof), so the CACP remedy is fallback submission. The demo separately
checks actual Bedrock channel tips to confirm inclusion.

The costly-escalation scenarios assert the exact balance deltas for both
participants and the neutral fee collector, and that proposal escrow returns to
zero after settlement.

Every funded Phase 3 setup also mutates only the wallet-generated Transfer
proof and asserts that B rejects that substituted FINALIZE before accepting the
untouched proof set.

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
5. Costly escalation: real CACP sessions construct a wallet-funded candidate.
   Both successful-response directions prove that the challenger pays the
   challenge fee, the responder pays the response fee, both stakes are refunded,
   and only the neutral-zone collector gains the two fees. Two unanswered
   challenge directions prove that the silent participant loses its stake while
   the challenger still pays its own challenge fee.
