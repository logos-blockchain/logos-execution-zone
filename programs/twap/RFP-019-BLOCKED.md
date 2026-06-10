# RFP-019 — what cannot be done here, and why

Items that are **blocked by something outside this repository** (a missing
dependency, tooling, or a non-code workstream), separated from items that are
merely "not done yet" (those are listed last and are not blocked).

## Blocked by RFP-004 (the LEZ DEX)

RFP-019 itself names RFP-004 a hard blocker: the oracle *reads pool accumulators
from the DEX*, so without the DEX there is nothing real to read. We substitute
`pool_stub`.

- **Read a real pool accumulator** — needs the RFP-004 DEX exposing tick
  accumulators. `pool_stub` only stands in for it.
- **Per-pool failure isolation** — needs multiple real, independently-failing
  registered pools, i.e. a real DEX with real pools.
- **Manipulation-cost analysis at $1M / $10M / $50M / $100M depth** — the attack
  cost is a function of the DEX's real liquidity curve and pool depth; it is
  meaningless against a stub. Needs RFP-004 parameters.

## Blocked by a missing admin-authority framework (RFP-001 / RFP-002, SPEL)

- **Owner-gated feed registration / deregistration** — requires an admin
  authority to define and enforce "the oracle program owner". No such authority
  module is available to gate it.
- **Per-pool governable `MAX_TICK_DELTA`** — requires owner governance to set the
  clamp per pool; same missing admin-authority dependency.

## Blocked by SPEL tooling

- **Publish the standard + program interface as a SPEL IDL** — the canonical
  price account must be a SPEL IDL artefact. It exists as a standalone Rust crate
  (`oracle_price`), but producing the mandated IDL needs the SPEL framework
  (<https://github.com/logos-co/spel>).

## Non-code / separate workstreams (not Rust on-chain logic)

- **Logos mini-app GUI dashboard** — a Logos Core module (C++/Qt) loadable in
  Basecamp; a separate codebase and UI, not part of the oracle program.
- **Figma designs for the dashboard** — a design deliverable.
- **SDK and CLI doc packets** — documentation deliverables (and the SDK/CLI
  surfaces they document).

## Blocked by repo infrastructure

- **Green CI on the default branch** — needs a CI pipeline configured for the LEZ
  repository (we are on a fork branch; no CI is wired).

---

## Not blocked — just not done yet (doable in code, no external dependency)

These need no missing piece; only more work:

- A pure read-only consult path (current `read_twap` writes the price account).
- Cardinality *expansion* of an existing pool (currently only set at init).
- Pool registration/deregistration **state-transition tests** (the mechanism
  itself is blocked above, but tests of any local state machine are not).
- CU-cost measurement of query / accumulator update / cardinality expansion
  (the harness `tools/cycle_bench` already exists in this repo).
