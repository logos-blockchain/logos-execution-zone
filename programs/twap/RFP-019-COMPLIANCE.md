# RFP-019 — requirement traceability

Status of each RFP-019 requirement against this implementation.
Legend: ✅ implemented · 🟡 partial · ❌ not yet implemented.

Code lives in: `oracle_price` (standard), `pool_stub` (DEX stand-in for RFP-004),
`twap`/`twap_core` (oracle), `examples/program_deployment/src/bin/run_twap_poc.rs`
(driver). Verified on a live local LEZ sequencer.

## Functionality

1. ✅ **TWAP reading accumulators + geometric mean over a configurable window** —
   `twap/src/read_twap.rs` reads `PoolAccount` and computes
   `tick_to_price(average_tick(Δcumulative, Δtime))`. Window is `window_ms`.
   Source is `pool_stub` (stands in for the RFP-004 DEX, which isn't available).
2. 🟡 **Tick accumulator + configurable cardinality (default 1, up to 65,535)** —
   `pool_stub_core::PoolAccount.obs` sized at `InitPool { cardinality: u16 }`
   (clamped ≥1). Configurable up to 65,535. Gaps: the driver uses 16, not the
   RFP default 1; **cardinality *expansion* of an existing pool is not implemented**
   (only set at init).
3. 🟡 **Query returns TWAP price + observation timestamps used** — price is
   computed and written; the specific observation timestamps used are not
   returned to the caller.
4. 🟡 **Canonical price account (base/quote/price/timestamp/source/confidence),
   standalone, reject invalid** — struct + standalone crate `oracle_price`
   (importable without the TWAP program); `assert!(price > 0)` in `read_twap`.
   Gap: it's a Rust struct, **not yet a SPEL IDL** artefact.
5. ❌ **Owner registers feed sources (add a pool)** — pools are created by
   `InitPool` + claim; no owner/admin gating, no register/deregister concept.
6. ✅ **maxAge staleness** — `read_twap(max_age_ms)`; `assert!(now - last ≤ maxAge,
   "Stale price")`.

## Usability & Tools

1. ❌ **SDK** — only a bespoke driver binary, not a reusable SDK.
2. ❌ **Mini-app GUI dashboard** (live TWAP, side-by-side vs another source, history).
3. ❌ **CLI** (query / expand cardinality / register / deregister).
4. 🟡 **Standalone IDL** — standalone crate done (`oracle_price`); **SPEL IDL not done**.
5. 🟡 **Clear error messages** — producer side: `"Stale price"`, `"Insufficient
   observations for window"`, `"Invalid price"`, `"Not the system clock account"`;
   consumer side: `ConsumeError::{PairMismatch, Stale, Unavailable}`. Gap: no
   explicit "cardinality too low for the requested window" message.
6. ✅ **Reference consumer + multi-source pattern** — `oracle_price::consume`
   verifies `(base_asset, quote_asset)`, enforces `maxAge`, and refuses on an
   unavailable (zero) price; `oracle_price::consume_multi` does primary + fallback
   on staleness with a divergence cross-check that flags but does not gate. Unit
   tested. Form: documented helper + tests (the RFP-permitted equivalent of a
   consumer program).

## Documentation

1. ❌ SDK doc packet (+ Recommended Consumer Pattern).
2. ❌ CLI doc packet.
3. ❌ Figma designs for the mini-app.
4. 🟡 README — repo README + `MATH_REFERENCES.md` exist; no full
   deployment/addresses/CLI/mini-app walkthrough.

## Testing & Reliability

1. 🟡 **Query is read-only** — divergence: `read_twap` **writes** the canonical
   price account (compute-and-publish model), so it is not read-only. A pure
   read-only consult path is not implemented.
2. ❌ **Atomic cardinality expansion** — expansion not implemented.
3. ❌ **Per-pool failure isolation** — single pool only.
4. ✅ **Deployed + tested on devnet/testnet** — verified live on a local LEZ
   sequencer (deploy → init → observe ×N → read → price).
5. 🟡 **E2E tests in CI, green** — e2e exercised via the driver; unit tests pass;
   **no CI wired**.
6. 🟡 **Test suite** — unit tests for TWAP correctness (`tick_to_price`,
   `average_tick`), **tick-delta truncation** (`clamp_tick_delta`), and
   consumer-side **staleness rejection** + **`(base,quote)` mismatch**
   (`oracle_price` tests). Gap: pool registration/deregistration state-transition
   tests not written.

## Performance

1. ✅ **Single-transaction query** — `read_twap` is one transaction.
2. 🟡 **Document CU cost** — not measured yet; `tools/cycle_bench` /
   `tools/crypto_primitives_bench` in this repo are the vehicle.

## Security

1. 🟡 **Block-boundary sampling** — `observe` samples once per clock-timestamp
   change (CLOCK_01 advances per block) and ignores same-block repeats; not an
   explicit "before same-block trades" guard.
2. ❌ **Min window + manipulation-cost analysis ($1M–$100M)** — not done.
3. 🟡 **Per-block tick-delta truncation (`MAX_TICK_DELTA = 9116`)** —
   `pool_stub_core::clamp_tick_delta` clamps the delta **before** the
   `tick_cumulative` update (`observe`). Gap: `MAX_TICK_DELTA` is a const, **not
   yet per-pool governable** by an owner.

## Soft requirements

1. ✅ **Multi-source consumer helper** — `oracle_price::consume_multi` returns a
   single result plus `Diagnostics { fallback_used, divergence_detected }`;
   primary feed with fallback on staleness, divergence cross-check logs but does
   not gate. Unit tested.

---

## Summary

The **on-chain core** is implemented and verified end-to-end on live LEZ: read
accumulator → geometric-mean TWAP (integer fixed-point) → per-block truncation
→ maxAge gating → write the canonical, standalone price-account standard.

Remaining work for the full RFP-019 deliverable: SPEL IDL for the standard;
owner-gated feed registration + cardinality expansion; SDK / CLI / mini-app /
reference consumer (incl. multi-source); CI + the remaining tests; CU-cost and
manipulation-cost analyses; per-pool governable `MAX_TICK_DELTA`; and swapping
`pool_stub` for the real RFP-004 DEX.
