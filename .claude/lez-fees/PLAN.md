# LEZ Fee Subsystem — Implementation Plan

Phase-2 plan implementing `.claude/lez-fees/SPECS.md` per erhant's decisions (no backwards compat; wire prefix bump to `/LEE/v0.4/`; everything restarts from genesis; producer pubkey in header; system txs fee-exempt; admission checks yes; genesis fee-exempt). Companion to `ANALYSIS.md` (file:line anchors there).

> **Superseded (2026-08-11):** wherever this plan says "wire v0.4" / prefix bump — erhant's final ruling is that ALL version prefixes stay at their committed values (`/LEE/v0.3/`, `/LEZ/v0.3/`); the fee wire-format changes ship under unchanged tags and version bumps happen in a separate later PR. T4 implemented this; T5/T6 must NOT bump prefixes.

## Assumptions & defaults chosen (TBA isolation)

Every TBA is isolated behind a single named seam; swapping the decision later touches only that seam (plus, at worst, one additive wire field — acceptable since compat is a non-goal).

| # | TBA | Seam (single point of change) | Provisional default built now | Must we wait? |
|---|-----|-------------------------------|-------------------------------|----------------|
| D1 | Q1 payer authorization (public) — **ANSWERED 2026-08-11** | wire-format fee authorization (T4) + `fee_core::authorize_payer` seam | Fees team ruling: the payer is any account whose **fee authorization** accompanies the tx — explicit designation plus a signature (or a program authorization) over the fee fields and the exact transaction they cover, per the transaction-format spec. Payer MAY be a signer, MAY be a third party outside the witness set (sponsored txs). MUST be designated explicitly, never inferred from the witness set. → T4 adds the fee-authorization structure to the wire format (payer designation is already a signed `Message` field; a third-party payer supplies a fee witness — payer pubkey + signature over the same tx hash); T4 also replaces fee_core's provisional payer∈signers rule (T1 shipped it under `// TBA(Q1)`) with authorization-validity checked at the wire/validation layer. Program authorization: defer behind the same seam until the ledger spec defines it. | Resolved. |
| D2 | Q2 program-deployment pricing — **ANSWERED 2026-08-11, then SUPERSEDED 2026-08-12** | `fee_core` deployment policy arm + deployment wire fields (T4 train) | Tokenomics ruled "folded into the public fee model" and T4 shipped the wire fields + authorization accordingly. **Standing decision (erhant 2026-08-12): deployments stay fee-EXEMPT** (storage-cap-counted, uncharged, `TBA(deployment-replay)`) until the replay-protection design is settled with the spec team — deployment messages have no nonces, so a charged-but-failed deployment would be re-includable forever. NOTE: `fee_core::deployment_policy()` still declares `PricedAsPublic` (the intent); the transition does not consume it — do not read fee_core alone as the shipped behavior. | Charging later = flip the marked site + add replay protection (uniform account_ids/nonces preferred). |
| D3 | Q3 + Q5-private (private payer & anti-replay) — **still OPEN, contested** | `fee_core::private_fee_payer(&PrivacyPreservingTransaction) -> Result<AccountId>` + settlement's nonce-advance hook | Private wire format gains a fixed-size `payer: AccountId` field now (needed anyway for the constant-size envelope; fixed 32 bytes, no size variance). Default rule: `payer` MUST be one of the tx's public signers (≥1 public signature required). Nonce-advance-on-settlement applies to that public account, same as Q5-public. Status 2026-08-11: tokenomics team calls private fee *funding* (burner accounts / relayer / fee program) out of scope for the fee spec; erhant disagrees and is pursuing it. INCREMENTIAL §6's collateral-account model is a competing answer. Spec side of Q5 now pinned: "an included tx consumes its replay protection whether it succeeds or reverts" (full invalid-vs-reverted design owned by execution/ledger specs). | Partially. The *wire field and hook* are safe now; the *rule* only changes this function + wallet UX later. **Shipped interim (T8, INCREMENTIAL parking): private txs are NOT charged and NOT payer-validated at all** — `authorize_private_payer` never runs; they are accepted uncharged and cap-counted. The earlier "fully-shielded txs rejected at fee-validity" default was superseded by the uncharged interim. |

## INCREMENTIAL.md exposure (added 2026-08-11)

`.claude/lez-fees/INCREMENTIAL.md` proposes account-state diffs (`AccountDiff` / `update_from_diff`) to fix the privacy-tx race condition. Its adoption status is **undecided**; if adopted it changes fee-relevant semantics. Tasks below marked ⚠️INCR carry the exposure; do not start the exposed *private-path* work until the ruling lands.

- **T5 ⚠️INCR (highest):** the privacy-tx journal gains `public_diffs` (compressed per-account) — the constant-size envelope's padding target and T3's byte model both change. T3's *methodology* (measured deltas) transfers; its numbers must be re-measured post-INCREMENTIAL.
- **T8 ⚠️INCR (high, private path only):** sequencer replays `update_from_diff` per public account touched by a privacy tx → (a) valid-proof-but-failed-update becomes a charged-failure class (fits our revert-keeps-fee semantics, but the classification rules are INCREMENTIAL §6's cases 2–3); (b) that replay is *variable sequencer execution work* not covered by a flat `PRIVATE_VERIFY_GAS` — either the fee model adds a capped/constant diff-replay allowance (preserves privacy invariant 3) or private fees stop being constant (INCREMENTIAL §8.2's stated con; a privacy regression the fee spec must rule on).
- **T2 (low):** if `update_from_diff` replay is metered, the metering plumbing gains a second consumer; the current cycle plumbing is compatible as-built.
- **T10 (medium):** INCREMENTIAL §7's mempool collision/anti-grift rules (nullifier-dedup by fee, nonce-dedup by fee, payable-fees admission requirement) extend the Q9 admission checks; design T10's admission layer so these rules slot in.
- **T11 (medium):** wallet proving/submission flow changes under diffs (account_ids instead of pre_states); fee estimation for privacy txs depends on the T8 ruling.
- **Q3 interaction:** INCREMENTIAL §6 assumes a collateral account for private fees — a competing/companion answer to the still-open Q3. One decision should cover both.

Other assumptions:

- **Fee state lives inside `V03State`** (new fields + the destructure guard at `lee/state_machine/src/state/mod.rs:306` forces every constructor/consistency site to acknowledge them). Rationale: both `ChainState` tiers and the indexer's scratch-clone path carry `V03State` verbatim; a wrapper struct would touch every one of those signatures for no benefit. Snapshot format breaks → testnet reset (approved).
- **`height` ≡ `block_id`**, genesis block (id 1) is fully fee-exempt (all its txs are system txs per Q6/Q10); the first fee-charging block is id 2; fee state is genesis-initialized per SPECS §Genesis.
- **Out-of-gas**: risc0 `session_limit` is a hard user-cycle limit that errors; we wrap it in a structured `LeeError::OutOfGas { consumed_at_limit }` detected via a dedicated executor wrapper (not string matching at call sites) and charge the full `gas_limit`.
- **Verification protocol** (per erhant's standing instructions): subagents run `cargo check -p <crate>`, `cargo +nightly fmt`, targeted `cargo test -p <crate> <test_name>` (with `RISC0_DEV_MODE=1` and `--all-features` where sequencer_core is involved) — never the full suite, never commit. erhant runs the suite and commits.
- Clippy bar: every task must leave `cargo clippy -p <touched-crates> --all-targets --all-features -- -D warnings` clean; `taplo fmt` for Cargo.toml edits.

## Task graph

```
Phase A (parallel): T1 fee_core │ T2 metering │ T3 size-measure tool
Phase B (wire v0.4): T4 public fields ← T1 │ T5 private envelope ← T3 │ T6 producer header
Phase C (consensus): T7 FeeState-in-state ← T1 │ T8 block transition ← T1,T2,T4,T5,T6,T7 │ T9 builder ← T8
Phase D (edges, parallel after C): T10 RPC/admission │ T11 wallet │ T12 indexer/FFI/explorer │ T13 genesis+configs
Phase E: T14 e2e integration tests ← all
```

---

### T1 — `fee_core` pure crate

**Goal:** All fee arithmetic and state types, dependency-free, cross-checked against SPECS Annex A/B.
**Files:** new `lez/fee_core/` (workspace member in root `Cargo.toml`): `params.rs` (all constants incl. genesis `MAX = 2·TARGET` validation), `state.rs` (`FeeState { base_fee_exec, base_fee_stor, escrow: u128, window: [u128; 50] + cursor, payout_carry, }` — Borsh; height stays the chain's `block_id`), `assess.rs` (`gas_stor`, `fee_reserve`, `fee_actual_base` over a `FeeTxView` enum abstracting `LeeTransaction`), `update.rs` (`next_base_fee`), `distribute.rs` (window push/payout/carry), `validity.rs` (static tx/block checks, `authorize_payer` D1 seam, `private_fee_payer` D3 seam, D2 policy arm), `error.rs`.
**Deps:** none.
**Verify:** unit tests transcribing SPECS Annex B's cross-check driver: the 8-block scenario table (exact printed tuples from the spec) + the LCG 10k-block fuzz final line as golden values; property tests for invariants 1–5 (conservation, bounded move, saturation, carry < 50, u64 fit); `cargo test -p fee_core`.

### T2 — metering plumbing (lee)

**Goal:** Deterministic per-tx user-cycle metering with a cumulative budget across chained calls; structured out-of-gas.
**Files:** `lee/state_machine/src/program/mod.rs` (`Program::execute(..., cycle_budget: u64) -> Result<(ProgramOutput, u64 /*cycles*/)>`; delete `MAX_NUM_CYCLES_PUBLIC_EXECUTION`, keep a protocol ceiling = `MAX_GAS_EXEC` for non-fee callers), `lee/state_machine/src/error.rs` (`OutOfGas` variant; wrapper distinguishing session-limit bail from other executor errors), `lee/state_machine/src/validated_state_diff/mod.rs` (`from_public_transaction(..., gas_limit) -> Result<(Self, cycles)>`: thread `remaining = gas_limit − used` into each chained call, sum user cycles), `lez/common/src/transaction.rs` (propagate cycles out of `validate_on_state`/`execute_on_state` — return `(diff, ExecutionOutcome)`).
**Deps:** none (merges before or in parallel with T4; call sites temporarily pass `MAX_GAS_EXEC` as the budget until T8 wires real `gas_limit`).
**Verify:** targeted tests in lee: a known guest (`test_methods::simple_balance_transfer`) returns a *stable* nonzero cycle count (pin the exact number — this doubles as the determinism regression test); budget below that count yields `OutOfGas`; chained-call test sums across sessions and halts mid-chain. `RISC0_DEV_MODE=1 cargo test -p lee <names>`.

### T3 — private envelope size measurement + constant re-pin

**Goal:** Real numbers for `PRIVATE_GAS_STOR` (envelope + proof + padded payload), replacing the spec's zero-envelope-overhead provisional value; a reusable measurement test so drift fails loudly.
**Files:** new test/bin in `lee/state_machine` (or `tools/`): construct maximal private txs (max public actions? — no: measure the *canonical padded form* defined in T5; this task first produces the raw component-size report: Borsh `InnerReceipt` real proof size — must confirm 223,551 — sig+pubkey pair size, per-`PrivateAction` size, enum tag/vec-len overhead).
**Deps:** none for measurement; T5 consumes the numbers. (A real STARK receipt is needed once — generate with `RISC0_DEV_MODE=0` for the one measurement, or reuse a committed fixture from `test_fixtures/`; flag runtime cost to the orchestrator.)
**Verify:** the measurement test itself asserts component sizes; report numbers back for the spec team to re-pin (feeds the SPECS TODO).

### T4 — wire v0.4: public fee fields

**Goal:** `payer: AccountId`, `gas_limit: u64`, `tip: u64`, `max_fee: u128` inside the signed public `Message`; prefix bumps.
**Files:** `lee/state_machine/src/public_transaction/message.rs` (fields + `PREFIX` → `/LEE/v0.4/…`), `transaction.rs`, all `Message::try_new`/`new_preserialized` call sites (wallet, programs facades, test_utils, sequencer's clock/deposit builders — mark system-tx construction with zeroed fee fields), `lez/common/src/block.rs` + private/deployment prefixes bumped in the same sweep (one atomic version bump for every domain prefix, incl. `HashableBlockData` PREFIX), pinned-hash tests updated.
**Deps:** T1 (for the validity checks tests reference); coordinates with T5/T6 (single wire-break PR train).
**Verify:** encoding-roundtrip + updated pinned-hash tests (`hash_public_pinned` etc. — recompute expected bytes); `cargo check -p lee -p common` and the tx-level unit tests.

### T5 — wire v0.4: constant-size private envelope (+ D3 payer field)

**Goal:** Every private tx serializes to exactly `PRIVATE_GAS_STOR` bytes (prod and dev mode).
**Files:** `lee/state_machine/src/privacy_preserving_transaction/` — new canonical envelope: fixed `payer: AccountId` field (D3), fixed-capacity encodings (cap + pad `public_actions`/`nonces`/`private_actions`/signature vec to protocol maxima — the caps become protocol constants; unpadded-payload bound `PRIVATE_PAD_BYTES` enforced in wire validity), proof slot padded to `PROOF_BYTES` (dev-mode fake receipts padded to the same slot — verifier strips padding before `borsh::from_slice::<InnerReceipt>`), wire-size equality check in `transaction_stateless_check` (`lez/common/src/transaction.rs:57`).
**Deps:** T3 (numbers), T4 (prefix train).
**Verify:** tests: any two constructed private txs (incl. dev-mode proof, zero vs max public actions) serialize to identical length == constant; roundtrip; padded-proof still verifies. Note for spec team: final `PRIVATE_GAS_STOR`/max-field caps go back into SPECS.

### T6 — producer in the block header

**Goal:** `producer: lee::PublicKey` header field; header signature verified against it in consensus; producer account derivable.
**Files:** `lez/common/src/block.rs` (`BlockHeader`, `HashableBlockData` — producer inside the hashed data), `lez/chain_state/src/apply.rs::validate_against_tip` (verify `is_signed_by(&header.producer)`), `into_pending_block` signature, sequencer construction sites, `is_signed_by` callers in `cross_zone_verifier`/indexer (can now use the embedded key; pinned-peer-key checks compare against it).
**Deps:** T4 (same wire-break train).
**Verify:** unit tests: valid block passes; wrong-key signature parks; tamper test updated. `cargo test -p chain_state -p common <names>`.

### T7 — FeeState into consensus state + genesis

**Goal:** Fee state persisted/reorged/finalized with everything else.
**Files:** `lee/state_machine/src/state/mod.rs` (`V03State { …, fee_state: FeeState }` — hits the line-306 destructure guard; `V03State::new()` initializes per SPECS §Genesis; accessor + `apply` hooks), `lez/fee_core` re-exported through `lee`; snapshot code needs no change (Borsh derives).
**Deps:** T1.
**Verify:** state roundtrip test incl. fee fields; genesis-values test; `cargo check -p lee -p chain_state -p sequencer_core -p indexer_core` (the destructure guard will enumerate every site to fix — that compile pass *is* the verification).

### T8 — block transition (the core task)

**Goal:** SPECS `block_transition` semantics in the shared apply path, used identically by sequencer follow/reconstruction and indexer replay.
**Files:** `lez/chain_state/src/apply.rs::apply_block_to_state` — restructure to: (1) static fee-validity + storage cap (system txs — clock tail, marked deposit-mints/dispatches, genesis block, D2 deployments — exempt from fees *and* caps per Q6); (2) per-tx reserve → execute (T2 cycles, `gas_limit` budget) → settle (charge `f_base + tip`, release remainder, **advance payer nonce at settlement** so charged failures can't replay — Q5); tx-level failure keeps fee, discards diff, block stays valid; reserve failure ⇒ block invalid; cumulative `MAX_GAS_EXEC` check as cycles land; (3) escrow/window/payout via `fee_core::distribute`, producer credit (`AccountId::from(&header.producer)`) last; (4) `next_base_fee` both resources; invariant checks (debug_assert + release-mode consensus-fault check for payout ≤ escrow). `ingest_error.rs` new variants. System-tx identification: clock = last-tx equality (as today, against v0.4 canonical form); deposit-mints/dispatches need a consensus-visible marker — use their existing structural signatures (`extract_bridge_deposit_id`, `extract_cross_zone_dispatch` — already pure functions over tx content) hoisted into `common` so validators classify identically.
**Deps:** T1, T2, T4, T5, T6, T7.
**Verify:** table-driven tests mirroring fee_core's golden scenario but through real `Block`s with mock-cycle guests; reorg test: fee state reverts with head rewind (`chain.rs` two-tier test); charged-failure test (revert keeps fee, nonce advanced, replay of same tx now nonce-fails); private-equality invariant test (all private txs in a block pay the same). `RISC0_DEV_MODE=1 cargo test -p chain_state <names> --all-features`.

### T9 — builder parity

**Goal:** `build_block_from_mempool` produces only blocks T8 accepts, and prices selection.
**Files:** `lez/sequencer/core/src/lib.rs` — budget selection by `gas_limit`/`data_bytes` against caps (replacing count/size-only limits; `max_block_size` remains as framing bound ≥ `MAX_GAS_STOR` + overhead), reserve-check before inclusion (drop tx if payer can't cover — that's the *builder's* prerogative; included-then-failed still charged), stop dropping execution-failures silently for *user* txs (include + charge, matching T8), system txs unchanged and exempt, admission of both tx streams unified through the same fee_core checks used by T8.
**Deps:** T8.
**Verify:** sequencer_core tests (`--all-features`, per memory note): block full-of-gas boundary, tip accounting, producer credit visible only next block, builder-vs-apply agreement (a built block re-applies cleanly through `apply_block_to_state` from the parent state — the key property test).

### T10 — RPC admission + fee queries

**Goal:** Q9 admission checks; clients can price txs.
**Files:** `lez/sequencer/service/src/service.rs` (admission: static fee-validity, `max_fee ≥ current reserve`, payer-balance ≥ reserve against head state), `lez/sequencer/service/rpc/src/lib.rs` (+ `get_fee_state`/`get_base_fees` returning base fees, next-block estimates, private fee quote).
**Deps:** T8 (fee state readable), T4.
**Verify:** service-level unit tests for accept/reject; `cargo test -p sequencer_service <names>`.

### T11 — wallet

**Goal:** Wallet builds fee-valid v0.4 txs.
**Files:** `lez/wallet/src/` (tx construction: payer defaults to first signer, `gas_limit` via dry-run estimate RPC or local executor + margin, `max_fee` from queried base fees + headroom factor, `tip` flag; delete vestigial `GasConfig` in `config.rs:22`), `lez/wallet-ffi` (surface fee params), keycard path needs no applet change (signs the 32-byte message hash; fee fields ride inside `Message`).
**Deps:** T4, T10.
**Verify:** wallet unit tests for fee computation; `cargo check -p wallet -p wallet-ffi`.

### T12 — indexer / FFI / explorer

**Goal:** Fee visibility downstream.
**Files:** `lez/indexer/core` (replay already correct via T8; expose fee state + per-block fee receipts — store `BlockReceipt`-like record per block), `lez/indexer/service` + `lez/indexer/ffi` (query methods; cbindgen regenerates `indexer_ffi.h` via build.rs), `lez/explorer_service` (display base fees/fees per tx). Downstream module flake bumps (`lez-indexer-module`, `lez-explorer-ui`) are **out of repo scope** — note for erhant.
**Deps:** T8.
**Verify:** indexer core tests (fee state matches sequencer's after replay — extend existing accept_block tests); `cargo check -p indexer_ffi` regenerating the header.

### T13 — genesis, configs, ops

**Goal:** Coherent deploy story from genesis.
**Files:** `lez/configs/*`, `lez/{sequencer,indexer}/service/configs/*`, `lez/testnet_initial_state` (fund testnet accounts amply for fees), docker compose docs, `Justfile` (`just clean` already resets stores — sufficient given no-migration), `docs/`.
**Deps:** T8–T12.
**Verify:** config deserialization tests; `cargo check` workspace.

### T14 — end-to-end integration tests

**Goal:** Lifecycle proof under `RISC0_DEV_MODE=1`.
**Files:** `integration_tests/` — scenarios: fee lifecycle (reserve/settle/refund visible in balances), congestion moves base fees up/down across blocks, private txs pay identically & fit ≤4/block, OOG tx charged at limit + nonce advanced, producer payout smoothing over 50 blocks (shortened via test constants? **No** — constants are protocol-fixed; run 60 blocks in-test), multi-sequencer producer credit to the right key, admission rejections. Rebuild committed artifacts if core crates changed guest-visible code (`just build-artifacts` — coordinate with erhant, slow).
**Deps:** everything.
**Verify:** each new test run individually by its author subagent; full suite is erhant's.

## Sequencing recommendation

Three PR trains on a feature branch (rebase-only, Conventional Commits): **(1)** T1+T2+T3 (no wire impact, land early, reviewable in isolation); **(2)** T4+T5+T6+T7 as the single coordinated v0.4 wire/state break; **(3)** T8+T9, then D-phase tasks in parallel, T14 last. The three TBA seams (D1/D2/D3) each carry a `// TBA(Qn):` marker comment so the later decisions are a grep away.

**Open items to relay to the spec team** (from this plan): Q6 deviation from invariant 6 (system-tx exemption); final `PRIVATE_GAS_STOR`/field-cap numbers from T3/T5; the Q5 nonce-advance-on-settlement rule; deployment-tx pricing (Q2) and private-payer rule (Q3) whenever ready.
