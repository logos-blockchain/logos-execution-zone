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

The bond is challenge-driven. A normal successful exchange needs no routine
on-chain confirmation: either party can close the bond by presenting both
signatures. Before staking, A commits to versioned canonical bytes containing
the exact funded Mantle transaction and its fee proof; B confirms the same
commitment when joining. If A says B withheld ACCEPT, A posts a challenge bond
and B must publish both those committed candidate bytes and its pre-committed
signature. If B says A withheld FINALIZE, B must publish the same complete
candidate and signature in the challenge. The chain data therefore gives A
everything needed to reconstruct FINALIZE instead of proving only that B once
signed an unavailable transaction.

A frivolous challenge loses the challenger's extra bond to the responder. An
unchallenged quiet-window timeout refunds both stakes; forfeiture is possible
only after an unanswered on-chain challenge. Like other optimistic protocols,
this requires participants or a watchtower to monitor the neutral zone during
the configured response window.

The program deliberately judges signature availability, not Bedrock inclusion:
the neutral execution zone cannot inspect another service's private mempool or
prove that a party received an off-chain packet. After Phase 3, both parties
possess the exact same fully signed Bedrock transaction (including the original
fee proof), so the CACP remedy is fallback submission. The demo separately
checks actual Bedrock channel tips to confirm inclusion.

The costly-abort scenarios also assert the exact participant balance delta and
that the proposal escrow balance returns to zero after settlement.

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
5. Costly abort: real CACP sessions construct a wallet-funded candidate. In one
   case B commits but withholds its ACCEPT signature; in the other A receives
   the full ACCEPT and creates but withholds FINALIZE. Dispute transactions make
   the committed candidate and proof available on-chain. The neutral
   `cacp_bond` program transfers escrow to the responding public account only
   after the relevant challenge window expires.
