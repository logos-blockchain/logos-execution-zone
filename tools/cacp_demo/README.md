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

There is no participant-selected fee collector. The bond program derives one
fixed, protocol-owned sink address from its own program ID. Native LEE balance
must remain conserved, so this demo implements burning as a transfer to that
sink; the bond program has no instruction that can withdraw it. A production
fee mechanism may route the value into the zone's protocol fee pool instead,
but A and B can never receive it.

Before joining, both parties review one `BondAgreement` containing the exact
funded Mantle transaction hash, both public LEE accounts, both Mantle Ed25519
keys, the stake, challenge fee, response fee and response window. Its agreement
ID also binds the bond program and fixed burn-policy versions. The program
recomputes that ID at `Open`. B's authorized `Join` signs the ID, so changing
even one economic field requires a different Join. This prevents A from
advertising a small response fee off-chain and then opening an unaffordable
one.

Each participant deposits `stake + challenge_fee + response_fee` before the
exchange. Challenge and response fees therefore come from prepaid escrow, not
new funds demanded at the deadline. Unused fee reserves are refunded at
settlement. Only stake is forfeitable.

The bond is challenge-driven. A normal successful exchange needs no routine
escalation: either party can close the bond by presenting both Ed25519
signatures over the agreed Mantle transaction hash. If A challenges, A's
prepaid challenge fee is burned and B must publish its signature; a valid
response burns B's prepaid response fee. The reverse direction works the same
way: B includes its signature while challenging and A must publish its own.

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
participants and the fixed burn sink, and that agreement escrow returns to zero
after settlement.

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
5. Costly escalation: the same two-channel builder constructs an exact
   wallet-funded Mantle transaction before either party joins the bond.
   Both successful-response directions prove that the challenger pays the
   challenge fee, the responder pays the response fee, both stakes are refunded,
   and only the fixed burn sink receives the two fees. Two unanswered
   challenge directions prove that the silent participant loses its stake while
   the challenger still pays its own challenge fee and both unused fee reserves
   are refunded.
