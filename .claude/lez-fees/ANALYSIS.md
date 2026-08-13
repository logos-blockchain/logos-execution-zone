# LEZ Fee Subsystem — Spec-to-Codebase Analysis

Phase-1 analysis for implementing `.claude/lez-fees/SPECS.md`. Maps every spec
requirement onto the current code, lists gaps and contradictions, and proposes a
workstream decomposition. File:line anchors are as of `dev` @ 87fca2a1.

---

## 1. Where things live today

### 1.1 Transactions and wire format

- `common::transaction::LeeTransaction` (`lez/common/src/transaction.rs:10`) is the
  block-level tx enum with **three** variants: `Public`, `PrivacyPreserving`,
  `ProgramDeployment`. The spec covers only public and private — **program
  deployment is unpriced** (see Gap G8).
- `lee::PublicTransaction` (`lee/state_machine/src/public_transaction/transaction.rs:10`)
  = `Message { program_id, account_ids, nonces, instruction_data }` + `WitnessSet`
  (sig+pubkey pairs). **No fee fields exist**: no `payer`, `gas_limit`, `tip`,
  `max_fee`. Signers are derived from the witness set; there is no distinguished
  fee-payer.
- `lee::PrivacyPreservingTransaction`
  (`lee/state_machine/src/privacy_preserving_transaction/`) = `Message {
  public_actions, nonces, private_actions, validity windows }` + `WitnessSet {
  signatures_and_public_keys, proof }`. Every field is a variable-length Vec and
  the proof is a Borsh-serialized Risc0 `InnerReceipt`
  (`circuit/mod.rs:21-41`) — **the private wire size is nowhere near constant
  today** (see Gap G3).
- Tx hashing is `SHA256(borsh(tx))` with domain prefixes
  (`public_transaction/message.rs:11`, block prefix `common/src/block.rs:117`).
  Adding fee fields **changes tx hashes, block hashes, and signatures** —
  a hard wire/protocol break, gated by the `/LEE/v0.3/` version prefixes.
- `data_bytes` would be `borsh::to_vec(&LeeTransaction).len()` as embedded in
  `BlockBody.transactions` — this is exactly what the block-size accounting in
  `build_block_from_mempool` measures today (`lez/sequencer/core/src/lib.rs:878`).

### 1.2 Block structure and production

- `common::block::Block` (`lez/common/src/block.rs:61`): header `{ block_id,
  prev_block_hash, hash, timestamp, signature }` + body (tx vec) +
  `bedrock_status`. **No producer identity in the header** — only an Ed25519
  signature, which is *not checked at all* in the shared apply path
  (`lez/chain_state/src/apply.rs:82` checks only hash/id/parent linkage), and is
  not pubkey-recoverable (see Gap G6).
- Producer loop: `SequencerCore::build_block_from_mempool`
  (`lez/sequencer/core/src/lib.rs:727`). Pops mempool txs FIFO
  (`lez/mempool/src/lib.rs` — a plain tokio channel, no fee ordering), validates
  each on a working clone of head state, **skips failures** (`lib.rs:939-951`,
  failed txs are simply not included), enforces `max_block_size` (default 1 MiB,
  `config.rs:98`) by serializing the whole candidate block, and
  `max_num_tx_in_block`. Every block ends with a **mandatory clock tx** —
  a canonical, *unsigned* public tx (`common/src/transaction.rs:233`,
  enforced by equality at `chain_state/src/apply.rs:132-137`).
- Sequencer-originated txs besides clock: bridge-deposit mints and cross-zone
  dispatches, drained from the store before user txs (`lib.rs:824-861`), executed
  via `transition_from_public_transaction` (bypasses system-account guards); the
  clock tx is likewise system-generated. **None of these has a payer** (Gap G7).

### 1.3 Validation / state transition

- Shared validate-then-apply entry point:
  `chain_state::apply::apply_block_to_state` (`lez/chain_state/src/apply.rs:125`)
  — used by the sequencer follow path, reconstruction, and (via
  `accept_block`) the indexer. This is the natural home of the spec's
  `block_transition`.
- **Any tx failure currently rejects the whole block** (`apply.rs:157-161`).
  The spec instead requires tx-level failures to keep the fee and discard
  effects while the block stays valid (Gap G5).
- Per-tx execution: `LeeTransaction::validate_on_state` / `execute_on_state`
  (`lez/common/src/transaction.rs:84,145`) →
  `ValidatedStateDiff::from_*_transaction`
  (`lee/state_machine/src/validated_state_diff/mod.rs:57,330,441`). The
  diff-then-apply structure already gives the spec's "transaction-local
  checkpoint" for free: a failing tx produces no diff, state untouched. What's
  missing is *charging the fee anyway*.
- Indexer replay path trusts inscriptions: `execute_on_state` skips the
  system-account guards (`transaction.rs:145-156`). Fee logic must live below
  that split so sequencer and indexer produce identical fee state.

### 1.4 Execution & metering (Risc0)

- Public execution *is* zkVM execution (no proving):
  `Program::execute` (`lee/state_machine/src/program/mod.rs:55-86`) runs
  `default_executor().execute(env, elf)` with
  `session_limit(32M)` (`mod.rs:15`, marked `TODO: Make this variable when fees
  are implemented`).
- **Metered user cycles are available**: `SessionInfo::cycles()` sums per-segment
  user cycles (risc0-zkvm 3.0.5, `host/api/mod.rs:405`) — deterministic,
  unaffected by `RISC0_DEV_MODE` (confirmed by
  `tools/cycle_bench/src/main.rs` header comment). Currently the value is
  **discarded** — only the journal is decoded.
- `session_limit` is a **hard limit on user cycles** (rv32im executor:
  `CycleLimit::Hard` compares `self.cycles.user`); exceeding it is an *error*
  (`bail!("Session limit exceeded")`), not a truncated session. So "halt at
  gas_limit" surfaces as a tx-level failure charged at `gas_limit`; there is no
  partial cycle count on the way out, and out-of-gas must be distinguished from
  other executor errors by error inspection (brittle — needs a wrapper).
- **One tx ≠ one session**: chained calls run one zkVM session per call
  (`validated_state_diff/mod.rs:108-127`, up to `MAX_NUMBER_CHAINED_CALLS = 10`).
  Per-tx metering must thread a cumulative budget: each call's
  `session_limit = gas_limit − cycles_used_so_far`, and `cycles(tx) = Σ sessions`.
  This requires plumbing a gas budget through `ValidatedStateDiff::
  from_public_transaction` → `Program::execute` and returning consumed cycles up.
- Private tx "execution" is a host-side STARK receipt verification
  (`circuit/mod.rs:34-41`); `PRIVATE_VERIFY_GAS` is a pricing constant, nothing
  to meter. ✅ matches spec.

### 1.5 Accounts, balances, state

- `Account { program_owner, balance: u128, data, nonce }`
  (`lee/state_machine/core/src/account.rs:92-103`) — balance is already `u128` ✅.
- `V03State` (`lee/state_machine/src/state/mod.rs:114`): `public_state:
  HashMap<AccountId, Account>`, `private_state: (CommitmentSet, NullifierSet)`,
  `programs`. Borsh-serialized wholesale into RocksDB (head + final snapshots,
  `lez/sequencer/core/src/block_store.rs:171`, `storage/`). Adding fee state
  fields breaks the snapshot format (DB reset or migration). A destructuring
  guard at `state/mod.rs:306` forces the decision when a field is added.
- `payer` maps to a **public** `AccountId` in both cases; a private tx today can
  have zero public signers (fully shielded), so a private payer needs a new
  authorized wire field (see Q3).
- Fee protocol state (`base_fee_exec/stor`, `escrow`, `window[50]`,
  `payout_carry`, `height`) has no home yet. It must revert/reorg with blocks,
  so it belongs in (or beside) `V03State` inside `ChainState`'s two-tier
  snapshots (`lez/chain_state/src/chain.rs`). Note `height` duplicates
  `block_id` (u64, genesis = 1, `lee_core::GENESIS_BLOCK_ID`, checked increments
  already at `lib.rs:770`); the spec's height starting at 0 vs LEZ genesis
  block_id = 1 needs a fixed mapping.

### 1.6 Producer identity & multi-sequencer

- Multi-sequencer turns exist (`is_our_turn`,
  `block_publisher.rs:382`; turn notifications from zone-sdk). Competing blocks
  at a height are resolved by the channel/finality (`lib.rs:632-661`).
- The producer's *L2 account* appears nowhere. `SequencerConfig.signing_key`
  (`config.rs:58`) signs blocks; `AccountId::from(&PublicKey)` exists, so
  producer-account = account of block-signing key is derivable **if the pubkey
  is in the block or known from a registry**. Header carries only a signature →
  needs a header field or an in-state sequencer registry (Gap G6, Q4).

### 1.7 RPC / wallet / indexer / FFI surfaces

- Sequencer RPC (`lez/sequencer/service/rpc/src/lib.rs`): `send_transaction`,
  `get_account*`, `get_block*` … Needs: current/base-fee query (wallets must
  price `max_fee` and private fees from public state, SPECS §Transactions), and
  admission-time fee checks in `service.rs:60-71` (today only size + stateless
  sig check).
- Wallet (`lez/wallet/`): builds and signs txs; has a **vestigial, unused
  `GasConfig`** (`config.rs:22-38`) from an older fee idea — replace. Needs
  payer/gas_limit/tip/max_fee UX, base-fee polling, private-fee computation.
- Indexer (`lez/indexer/core`): replays blocks through the same
  `accept_block`/apply path; explorer + `indexer_ffi` + `lez-indexer-module`
  would want base-fee/fee-history queries (new FFI methods → cbindgen header
  regen → module flake bumps, per workspace CLAUDE.md).
- `tools/cycle_bench` exists in-repo and measured the numbers in SPECS Annex C.

### 1.8 L1 touchpoints (verified no conflict)

- L1 posting is funded by the zone-sdk node wallet: `BedrockConfig { funding_key,
  priority_fee }` (`lez/sequencer/core/src/config.rs:73-83`) →
  `FundingConfig { funding_pk, max_tx_fee, priority_fee }`
  (`logos-blockchain/zone-sdk/src/sequencer/types.rs:134`). Out-of-band exactly
  as the spec scopes it; the fee mechanism reads nothing from Bedrock. ✅
- Blocks are opaque `ZoneMessage::Block` bytes to the L1; changing the L2 wire
  format does not touch the zone-sdk contract.

---

## 2. Gaps and contradictions (spec ⇄ code)

**G1 — No fee fields in the wire format.** `payer`, `gas_limit`, `tip`,
`max_fee` must be added to the public tx message (signed ⇒ inside the hashed
`Message`, not the witness set). Breaks tx/block hashes and every signer,
including hardware (`keycard_wallet`) and the PPE circuit's message hash for
private txs if their message changes. Version-prefix bump (`/LEE/v0.4/`?)
recommended.

**G2 — No metering plumbed.** Cycle counts exist (`SessionInfo::cycles()`) but
are discarded; no cumulative per-tx budget across chained calls; out-of-gas is a
string error. Requires an `ExecutionOutcome { cycles, … }` return through
`Program::execute` → `ValidatedStateDiff` → `execute_on_state`, and replacing
the fixed 32M `MAX_NUM_CYCLES_PUBLIC_EXECUTION` with the tx `gas_limit` budget.
Also note: **executor cycle counts must be identical across risc0 versions** —
a risc0 upgrade becomes a consensus-breaking protocol-version change.

**G3 — Private tx size is not constant.** Variable vecs, variable ciphertexts,
variable signature count, ~223 KB proof. The spec's `PRIVATE_GAS_STOR` requires
envelope-level padding of the whole private tx to a constant canonical size, and
the current `PRIVATE_GAS_STOR = 224,063` assumes zero envelope overhead — the
real envelope (enum tag, vec lengths, pubkeys, windows…) must be measured and
the constant re-pinned (SPECS' own TODO). Also `RISC0_DEV_MODE` fake receipts
are tiny — dev-mode padding must still hit the same constant size or dev/prod
diverge on `data_bytes`.

**G4 — Reverted-tx replay / nonce question.** Spec: tx-level failure discards
execution effects but keeps the fee. If the discarded effects include the nonce
increment, the *same signed tx* can be re-included every block, draining the
payer's balance via fees with no user action. Needs an explicit rule (advance
payer nonce on charged failures, EIP-1559-style) — currently nonces only advance
inside successful diffs. **Spec is silent; must be decided** (Q5).

**G5 — Block-validity semantics flip.** Today any failing tx rejects the whole
block (`apply.rs:157`); builder pre-filters failures so it never happens in
practice. Spec requires: reserve-failure ⇒ reject block; execution
failure/revert ⇒ keep tx, charge fee, discard effects. The shared apply path
and the builder's skip-on-failure logic (`lib.rs:939`) both change: an included
failing tx becomes *normal*, and the builder must stop dropping them (or it
under-charges vs. peers who validate its block).

**G6 — No producer account.** Header has an unverified signature, no pubkey, no
producer id; the payout credit target does not exist. Needs a `producer`
(pubkey or AccountId) header field + signature verification in the shared apply
path, or a consensus-known sequencer registry. Note the multi-sequencer work
(PR 603 line) intersects here.

**G7 — System/sequencer transactions have no payer.** Clock tx (mandatory,
unsigned, canonical — equality-checked at `apply.rs:135`), bridge-deposit
mints, cross-zone dispatch deliveries. Spec's invariant 6 says producer pays
for its own txs; the clock tx literally cannot carry a payer today without
breaking its canonical-equality check. Decide: exempt system txs (spec change)
or make producer the payer (wire + validation change + producer must keep a
funded account; and a deposit-mint whose producer can't pay blocks bridge
liveness) (Q6).

**G8 — Program deployment is unpriced and unsigned.**
`from_program_deployment_transaction` (`validated_state_diff/mod.rs:441`)
accepts any bytecode from anyone for free; it's also by far the largest public
tx (whole ELF on-chain ⇒ storage gas would price it heavily; execution gas ~0).
The spec doesn't mention this tx kind at all (Q2).

**G9 — Genesis & state-format migration.** Genesis fee state per SPECS §Genesis;
`MAX_GAS_r = 2·TARGET_GAS_r` validation; fee state fields break Borsh snapshot
compat (testnet reset vs migration, Q8). Genesis block (id 1) contains
`GenesisAction` supply txs — presumably fee-exempt (height 0 → first fee block
mapping must be pinned).

**G10 — Mempool/admission has no fee awareness.** FIFO channel; no
`max_fee`-vs-current-base-fee admission check, no tip ordering, no per-payer
balance check at admission. Minimal viable: admission-time static fee-validity
+ balance check; ordering by tip is optional per spec.

**G11 — Storage-cap vs `max_block_size` overlap.** `MAX_GAS_STOR` = 1,000,000
bytes of *transaction* bytes; `max_block_size` = 1 MiB of *whole block*
including header/framing (producer-borne per spec). The two coexist but the
config value must be ≥ storage cap + framing; ideally `MAX_GAS_STOR` becomes
the consensus cap and `max_block_size` a derived/operational bound.

**G12 — `escrow`/`window`/`payout_carry` conservation vs supply.** Balances are
u128 and supply 10¹⁹ < u64::MAX ✅; but fee debits/credits must not collide
with the bridge-escrow accounting guards (`validate_bridge_account_modification`)
— fee settlement happens outside program execution, so guards are unaffected as
long as fee logic runs at the block layer, not as a program.

---

## 3. Proposed workstreams (dependency order)

**W0 — fee-core crate (pure).** New `lez/fee_core` (or `lee/fee`): constants,
`FeeState`, `next_base_fee`, reserve/settle arithmetic, window/payout, all
integer-only u64/u128, mirroring SPECS Annex B; property tests + cross-check
against the Python/Rust reference vectors. No deps on the rest of LEZ.
*Blocks nothing; everything depends on it.*

**W1 — wire format.** Fee fields in public `Message`; private envelope with
constant-size padding; re-pin `PRIVATE_GAS_STOR`/`PRIVATE_PAD_BYTES`; version
prefixes; producer identity in the header (pending Q4); `data_bytes`
definition. *Depends: Q1–Q4, Q6.*

**W2 — metering.** `ExecutionOutcome{cycles}` through `Program::execute`,
cumulative budget across chained calls, structured out-of-gas error,
`gas_limit` replaces the 32M constant. *Independent of W1.*

**W3 — block transition.** Fee state into `ChainState`/`V03State` snapshots;
reserve→execute→settle in `apply_block_to_state` + builder parity in
`build_block_from_mempool`; tx-failure-keeps-fee semantics; caps; escrow/
window/payout; producer credit; invariants as debug/consensus checks.
*Depends: W0–W2.*

**W4 — admission & mempool.** RPC static fee-validity, balance pre-check,
(optional) tip ordering. *Depends: W1, W3.*

**W5 — client surfaces.** Base-fee RPC on sequencer+indexer, wallet fee UX
(max_fee, gas_limit estimation via dry-run executor, private fee preview),
explorer/FFI/module plumbing. *Depends: W3.*

**W6 — genesis/config/migration + e2e.** Genesis validation, testnet reset
story, integration tests (RISC0_DEV_MODE=1), `just build-artifacts` refresh,
cross-check harness vs SPECS Annex A. *Last.*

---

## 4. Risks

1. **Consensus determinism of cycle counts** across risc0 versions/platforms —
   pin risc0 exactly; treat upgrades as protocol versions. Executor user-cycles
   are documented deterministic, but this is the single riskiest assumption:
   validate with a multi-platform CI check early.
2. **Wire-format break blast radius**: wallet, keycard hardware signing, PPE
   circuit output hashing, cross-zone peers, FFI modules, explorer — one
   coordinated cutover.
3. **Fee-state snapshot compat**: every stored V03State (sequencer + indexer +
   wallet-side caches) resets or migrates.
4. **Out-of-gas detection via error strings** — needs a structured error from
   the risc0 wrapper, else spam txs could be mis-classified as consensus faults.
5. **Producer liveness vs producer-pays** for system txs (clock/deposits):
   an underfunded producer halts its own block production.
6. **Private-fee UX**: payer account funding "without linking identities" is
   out of scope for the spec but *not* for a usable testnet — the wallet team
   needs at least a stopgap (public payer account) and that stopgap leaks
   linkage; flag to product.
