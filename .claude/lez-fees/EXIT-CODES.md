# Guest exit codes instead of panics — feasibility

**Verdict: amenable, with caveats.** risc0 gives us exactly the primitive the proposal assumes, the
host-side seam is two functions wide, and the fee settlement arm needs *no* change at all. The cost
is guest churn (~222 sites across 16 programs) and a mandatory artifact rebuild that changes every
program image ID.

Scope of this doc: the *public* execution path (`Program::execute` → `validated_state_diff` →
`apply_charged`). That is the only path that meters cycles for fees.

---

## 1. How guests fail today

Every LEZ guest is `fn main()` with no return value. The only exit from a failed execution is a
Rust panic, which the risc0 guest runtime turns into `sys_panic` and the host turns into an
`anyhow::Error` — with **no `SessionInfo`**, therefore no cycles.

### Catalog (program guests, `#[cfg(test)]` bodies excluded)

`lez/programs/*/src/**` — 34 files, 3 449 loc, **222 failure sites**:

| Form | Count | Convertible to an exit code? |
|---|---|---|
| `.expect(...)` | 92 | Yes — almost all are user-facing revert conditions, not invariants |
| `assert!` | 55 | Yes |
| `assert_eq!` | 53 | Yes |
| `panic!` | 17 | Yes |
| `.unwrap()` | 2 | Yes |
| `unreachable!` | 2 | Judgment — genuine "can't happen" arms |
| `assert_ne!` | 1 | Yes |

Per program (loc / panic / unwrap+expect / assert):

```
amm            1270  8  29  41      cross_zone_inbox  527  3   9  21
token           854  5  31  22      bridge            253  2   2   9
associated_ta   298  0   6   3      wrapped_token     279  3   6  12
bridge_lock     180  2   4   7      cross_zone_outbox 165  1   3   5
vault           147  0   3   2      faucet            139  0   2   3
clock           136  3   4   0      pinata_token      118  0   2   2
authenticated_t 115  0   4   2      pinata             94  0   4   2
ping_sender      59  0   1   1      ping_receiver      48  0   2   2
```
(counts include each program's `core/` crate; see the split below)

The `.expect` messages confirm these are reverts, not invariants — a sample of the 92:
`"Sender has insufficient balance"`, `"Insufficient balance to burn"`, `"Total supply overflow"`,
`"Transfer requires exactly 2 accounts"`, `"payload decodes to a wrapped-token instruction"`,
`"Token A should have a nonzero amount"`, `"reserve * amount_out overflows u128"`.

### Shared `*_core` crates are a different population

`lez/programs/*/core/src/**` — 12 files, 1 227 non-test loc, **28 sites**: 18 `.expect`,
7 `unreachable!`, 1 `assert!`, 1 `assert_eq!`, 1 `panic!`. These compile for the **host too**
(the wallet links `token_core` etc.), so they cannot call `env::exit`. Their messages are genuine
invariants (`"Serialization to Vec should not fail"`, `"Token definition encoded data should fit
into Data"`). **Leave them alone.**

### SDK layer

`lee/state_machine/core/src/program/mod.rs`:

- **`read_lee_inputs`** (`:645-662`) — line **652** is
  `T::deserialize(&mut Deserializer::new(instruction_words.as_ref())).unwrap()`. This is the
  **only attacker-controlled deserialization in the guest** (`instruction_data` comes straight off
  the transaction). Today a malformed instruction payload is an uncatchable guest panic, i.e. a
  free-to-produce full-budget charge. High-value single-line fix.
- The three preceding `env::read()` calls read host-constructed values (program id, caller id,
  pre-states); those are well-formed by construction.
- **`ProgramOutput::write`** (`:470-472`) is just `env::commit(&self)`. There is no entry/exit
  macro, no `Result`-returning main convention, nothing to hook. Each program's `main` is
  hand-rolled (see `lez/programs/token/src/main.rs`).

### Early `return` without writing output — already a distinct, cheaper failure

Several test guests do `let Ok([a, b]) = <[_;2]>::try_from(pre_states) else { return; };`
(`lee/state_machine/test_methods/guest/src/bin/missing_output.rs`, `extra_output.rs`, …). What the
host sees: the session **completes** with `Halted(0)` and an **empty journal**, so
`default_executor().execute()` returns `Ok(SessionInfo)` *with cycles*, and then
`Program::execute` (`lee/state_machine/src/program/mod.rs:95-98`) throws them away because
`journal.decode()` fails:

```rust
let cycles = session_info.cycles();                       // :92  — measured!
let program_output = session_info.journal.decode()
    .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;   // :95-98 — discards `cycles`
```

**This is a bug independent of the exit-code proposal**: a class of failures already has exact
cycles available and is billed at zero execution gas. Worth fixing on its own.

### Test guests

`lee/state_machine/test_methods/guest/src/bin/` — 29 guests, 32 sites (14 `.expect`, 6 `panic!`,
6 `assert!`, 5 `.unwrap()`, 1 `assert_eq!`). Only those whose tests assert on the *kind* of failure
need touching.

---

## 2. risc0 3.0.5 mechanics — the facts, with evidence

Registry root: `/Users/erhant/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`

**(a) `env::exit(code)` exists and always finalizes the journal.**
`risc0-zkvm-3.0.5/src/guest/env/mod.rs:180-183`
```rust
pub fn exit(exit_code: u8) -> ! { finalize(true, exit_code); unreachable!(); }
```
`finalize` (`:157-175`) hashes whatever was committed into a journal digest and passes it to
`sys_halt(user_exit, &output_words)` — **the journal is committed regardless of the exit code**.
Codes are `u8` (0–255).

**(b) A nonzero halt is `Ok`, not `Err`, and carries full cycle accounting.**
`risc0-zkvm-3.0.5/src/host/server/exec/executor.rs:256` computes
`exit_code_from_terminate_state(...)` which maps `halt::TERMINATE` to `ExitCode::Halted(user_exit)`
for *any* user exit (`risc0-zkvm-3.0.5/src/claim/receipt.rs:310-324`) — no `bail!`.
`risc0-zkvm-3.0.5/src/host/client/prove/local.rs:60-79` then returns
`Ok(SessionInfo { segments, journal, exit_code, receipt_claim })`. `SessionInfo::cycles()`
(`src/host/api/mod.rs:403-409`) sums per-segment user cycles. **So a guest that exits nonzero gives
us exact cycles.** This is the load-bearing fact.

**(c) The journal survives a nonzero exit.**
`executor.rs:258-268`:
```rust
let session_journal = result.claim.output.and_then(|digest|
    (digest != Digest::ZERO).then(|| std::mem::take(&mut *journal.buf.lock().unwrap())));
if !exit_code.expects_output() && session_journal.is_some() { /* debug log only */ }
```
and `risc0-binfmt-3.0.4/src/exit_code.rs:88-93`:
```rust
pub fn expects_output(&self) -> bool {
    match self { ExitCode::Halted(_) | ExitCode::Paused(_) => true,
                 ExitCode::SystemSplit | ExitCode::SessionLimit => false }
}
```
`Halted(n)` expects output for **any** `n`, so the journal is retained. That means the host must
*decide* to ignore it when `n != 0`, and it also means a guest could optionally commit a structured
revert payload before exiting. See §3 for the rule.

**(d) A guest panic is an `Err` with no `SessionInfo` — the problem, confirmed.**
The Rust panic handler is `risc0-zkvm-platform-2.2.2/src/rust_rt.rs:30-34` →
`sys_panic`, and the host handler is
`risc0-zkvm-3.0.5/src/host/server/exec/syscall/panic.rs:41`:
```rust
bail!("Guest panicked: {msg}");
```
This propagates out of `exec.run` → `run_with_callback` → `execute` as `Err`. Nothing is
recoverable from it.

**(e) Panics cannot be caught in-guest.** `risc0-build-3.0.5/src/lib.rs:488` compiles guests with
`-C panic=abort`, and `:408` builds std with `panic_abort`. `catch_unwind` is therefore not an
escape hatch. Confirms hard-case (a) below.

**(f) `session_limit` is orthogonal and unchanged.**
`risc0-circuit-rv32im-4.0.4/src/execute/executor.rs:243-249` bails with
`"Session limit exceeded: {n} >= {max}"` from inside the run loop — also no `SessionInfo`. LEZ
already special-cases that string (`lee/state_machine/src/program/mod.rs:15, :132-148`) and meters
it at the whole budget. **An exit-code refactor does not touch this path**; a guest that exits with
a code before hitting its limit produces exact cycles below the budget, and a guest that hits the
limit still bails. Note `ExitCode::SessionLimit` is documented as never produced
(`risc0-binfmt-3.0.4/src/exit_code.rs:55-59`).

**(g) Proving requires `Halted(0)` — matters only for the private path.**
`risc0-zkvm-3.0.5/src/receipt.rs:160-201`: `Receipt::verify` builds `ReceiptClaim::ok(...)` and
compares digests, so a receipt with `Halted(1)` fails `verify`. In the wallet's
`execute_and_prove_with_padded_inputs`
(`lee/state_machine/src/privacy_preserving_transaction/circuit/mod.rs:106-141`) each program
receipt is fed to `env_builder.add_assumption(...)`. A nonzero-exit receipt could never compose.
This is fine: in the private path a failing program means the wallet cannot build a transaction at
all — nothing reaches consensus, nothing is billed.

**(h) Arithmetic overflow is *not* a panic source in guests today.** Neither the root
`Cargo.toml` nor `lez/programs/Cargo.toml` sets `[profile.release] overflow-checks`, and
`cargo risczero build` builds release. Overflow **wraps silently**. (Which is why the programs are
full of `checked_sub(...).expect(...)` — and it means overflow drops out of the residual-panic
list, though it stays a correctness footgun worth its own ticket.)

---

## 3. Host-side shape

### `Program::execute` (`lee/state_machine/src/program/mod.rs:69-101`)

Only two call sites exist: the chain loop (`validated_state_diff/mod.rs:211`) and
`program/tests.rs`. Change the return type:

```rust
pub(crate) enum ProgramRun {
    Completed { output: Box<ProgramOutput>, cycles: u64 },
    Reverted  { code: u8, cycles: u64 },
}

// inside execute(), after `let session_info = execute_session(env, self.elf(), cycle_budget)?;`
let cycles = session_info.cycles();
match session_info.exit_code {
    ExitCode::Halted(0) => {
        let output = session_info.journal.decode()
            .map_err(|e| LeeError::MalformedProgramOutput { cycles, reason: e.to_string() })?;
        Ok(ProgramRun::Completed { output: Box::new(output), cycles })
    }
    // Journal deliberately ignored: `expects_output()` keeps it alive on a nonzero halt, but a
    // reverting program has no state diff to contribute.
    ExitCode::Halted(code) => Ok(ProgramRun::Reverted { code: code as u8, cycles }),
    other => Err(LeeError::ProgramExecutionFailed(format!("unexpected exit: {other:?}"))),
}
```

**"No output because reverted(code)" vs "malformed guest" is unambiguous**: the exit code decides,
before the journal is even looked at. `Halted(0)` + undecodable journal = a buggy program (today's
silent early-`return`); `Halted(n≠0)` = a revert. Both now carry cycles — the malformed case needs
`cycles` threaded onto the error (a new `LeeError` variant or an out-param mirroring the existing
`cycles_used: &mut u64` style).

### Chain loop (`validated_state_diff/mod.rs:186-410`)

The `match program.execute(...)` at `:211-245` gains one arm:

```rust
Ok(ProgramRun::Reverted { code, cycles }) => {
    *cycles_used = cycles_used.saturating_add(cycles);
    return Err(LeeError::ProgramReverted { program_id: chained_call.program_id, code });
}
```

and the `TBA(revert-metering)` comment block at `:235-244` deletes. `ExecutionOutcome`'s doc
(`:49-65`) loses its "the executor discards the failing session's count" paragraph.

### Fee settlement — **no change required**

`lez/chain_state/src/apply.rs:599-626` already does:

```rust
let (outcome, result) = ValidatedStateDiff::from_public_transaction_metered(...);
let charged_cycles = outcome.cycles.min(gas_limit);            // :605
...
Err(err) => { state.advance_replay_nonces(&signers);
              summary.tx_outcomes.push(TxApplyOutcome::Reverted { reason: ... }); }   // :618-625
```

Exact-cycle billing slots straight into `charged_cycles` — the revert arm already exists, the clamp
already exists, `fee_actual_base(charged_cycles, ...)` already prices it. This matches
`SPECS.md:132` ("A transaction that fails, reverts, or halts at its limit is charged for the cycles
consumed to that point"), which the interim full-budget charge currently violates.

Optional nicety: widen `TxApplyOutcome::Reverted` (`apply.rs:76-84`) with `code: Option<u8>` so the
explorer can show *why*.

### Tests that pin the current behaviour and will flip

- `lee/state_machine/src/validated_state_diff/tests.rs:664-685`
  `a_guest_panic_meters_only_the_sessions_that_completed` — asserts `outcome.cycles == 0`.
  Written to fail loudly when this lands (`:663`).
- `lez/chain_state/src/apply.rs:1226-1257` — the mirrored block-level pin.

---

## 4. Hard cases

**(a) Panics the program does not control.** With `panic=abort` (§2e) there is no in-guest catch.
The residue after the refactor:

| Class | Present in LEZ guests? |
|---|---|
| Arithmetic overflow | **No** — overflow-checks off, wraps (§2h) |
| Dynamic OOB indexing | Rare — programs destructure fixed-size arrays via `try_into().expect(...)`, which becomes a code |
| Division by zero | ~9 `/` or `%` occurrences total, mostly by constants |
| Allocator exhaustion | `risc0-zkvm-platform-2.2.2/src/heap/bump.rs:94` → `sys_panic`. Only on pathological allocations |
| Stack overflow | Possible, unbounded recursion only |
| Panics in third-party guest deps | Possible |

So **essentially 100% of the *deliberate* failure signals convert** (222/222 program-controlled
sites), and the panic-only residue is genuine bugs plus resource exhaustion. But —

> **A deployed program is user-supplied bytecode and can always choose to panic.** The full-budget
> charge must remain as the fallback arm forever. It is not a stopgap; it is the correct price for
> an uncooperative program, and it is what keeps this from becoming a spam discount. The exit-code
> mechanism is a *cooperation* incentive for well-behaved programs, not an enforcement mechanism.

This has a flip side worth a decision: exact-cycle billing makes cheap reverts *cheap*, which
lowers the cost of spamming failing transactions relative to today's full-budget charge. SPECS
already rules for exact cycles, so this is a ratification, not a new question — but it should be
stated in the PR.

**(b) Mid-chain revert.** Expressible and clean. The chain shares one cumulative budget
(`:194`, `remaining_cycles = cycle_budget - cycles_used`) and `cycles_used` accumulates per link
(`:246`). A revert at link 3 stops the chain — same as today (the whole transaction reverts and
`state_diff` is discarded; there is no partial-chain commit) — but now the outcome carries
links 1+2 (already exact) **plus** link 3 (newly exact). Strictly better, no new semantics.
`MAX_NUMBER_CHAINED_CALLS = 10` (`lee/state_machine/core/src/program/mod.rs:14`) is unaffected;
exceeding it is a host-side `ensure!`, not a guest failure.

**(c) The privacy-preserving circuit — out of scope.** `lee/privacy_preserving_circuit/src/**`
(967 loc, 42 failure sites: 18 `assert_eq!`, 10 `assert!`, 9 `.expect`, 4 `panic!`,
1 `unreachable!`) is proved **client-side** by the wallet (`circuit/mod.rs:152-156`) and only
*verified* on-chain (`validated_state_diff/mod.rs:646-669`). Its failures are "the wallet cannot
build a transaction" and "the proof is invalid" — and `SPECS.md:100` rules that an invalid private
proof is an *invalid* transaction, not a reverted one: it cannot be included, so nothing is billed.
`ExecutionOutcome::FREE` is used for every non-public transaction
(`validated_state_diff/mod.rs:46-47, 67-70`). **Do not touch it in this PR.** §2g additionally
shows exit codes would actively break receipt composition there.

**(d) "Guest wrote no output" as a protocol state.** Today it collapses into
`LeeError::ProgramExecutionFailed` via a journal-decode error, and the shape is already policed
downstream (`InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput`,
`MismatchedPreStatePostStateLength`, `DefaultAccountModifiedWithoutClaim`). After the refactor it
splits cleanly in two — `Halted(0)` + no journal = malformed program; `Halted(n≠0)` = revert — and
**both become billable at exact cycles**, closing the current zero-charge hole. No protocol rule
depends on the two being conflated.

---

## 5. PR scale

| Layer | Files | Sites | Character |
|---|---|---|---|
| Guest SDK (`lee_core::program`) | 1 | ~5 | New: `revert(code) -> !`, code constants, `require!` macro, `OrRevert` ext trait; fix `:652` `.unwrap()` |
| `lee/state_machine/src/program/mod.rs` | 1 | ~40 loc | New `ProgramRun` enum, exit-code match, journal-decode fix |
| `lee/state_machine/src/error.rs` | 1 | +2 variants | `ProgramReverted { program_id, code }`, `MalformedProgramOutput { cycles }` |
| `validated_state_diff/mod.rs` | 1 | ~25 loc | One new match arm, delete the `TBA` block, update `ExecutionOutcome` docs |
| **Program guests** | **34** | **222** | Mechanical *edit*, per-program *judgment* on the code table |
| Test guests (`test_methods`) | ≤29 | ≤32 | Only where tests assert failure kind |
| Fee settlement (`apply.rs`) | 1 | ~0 | Optional `code` on `Reverted`; the clamp already works |
| Pinned tests | 2 | 2 | `tests.rs:664`, `apply.rs:1226` flip from "cycles lost" to "cycles exact" |

**Effort:** 1–2 days if you adopt a flat scheme (`0` = ok, `1` = generic revert, a handful of
SDK-reserved codes, rest program-defined and unused at first). 3–5 days if each program gets a
real error enum with stable numbering — which is the version worth having, since the code is the
only thing a user or explorer will see.

**Suggested split.** Two PRs, because the second one is the expensive one:

- **PR-A (host only, no guest churn, no artifact rebuild).** Fix the journal-decode path so
  `Halted(0)` + undecodable output keeps its cycles; land the `ProgramRun` shape and the
  `Reverted` arm even though no guest emits codes yet. Zero image-ID churn, immediate win on the
  early-`return` class.
- **PR-B (guest churn).** SDK helper + 222 sites + artifact rebuild + fixture regeneration.

### Wire / state break — **yes, unavoidably, in PR-B**

- The **journal shape does not change** on the success path: `ProgramOutput` is untouched, and a
  revert commits nothing. So no serialization break.
- But **every guest ELF changes**, and `ProgramId` *is* the risc0 image ID
  (`lee/state_machine/src/program/mod.rs:24-32`). So **all 17 committed artifacts change and every
  program ID changes**:
  - `just build-artifacts` is mandatory (rebuilds `artifacts/lez/programs/*.bin`; the privacy
    circuit is untouched but the Justfile rebuilds it too).
  - `lez/testnet_initial_state/src/lib.rs:224-262` deploys programs by `programs::x().id()` and
    `:162, :198` set `program_owner` from them → **genesis state changes**.
  - `test_fixtures/fixtures/prebuilt_sequencer_db.dump` must be regenerated.
  - Any live testnet is a fresh-genesis restart, and any address derived via
    `AccountId::for_public_pda(program_id, seed)` moves.

That is a hard fork of the program set, not a soft change. It is the same cost as any guest edit,
so the right move is to batch it with whatever other guest-affecting work is queued.

---

## 6. Recommendation

Do it, in the two-PR split above.

The mechanism is sound: risc0 gives `Ok(SessionInfo)` with exact cycles on any `Halted(n)`
(§2b), the journal survives so the host can decide policy rather than guess (§2c), and the fee
settlement path needs *no* structural change because `charged_cycles = outcome.cycles.min(gas_limit)`
already prices whatever the executor reports (`apply.rs:605`). It moves the implementation onto the
side of `SPECS.md:132` it is currently on the wrong side of.

Two things to say out loud in the PR description:

1. **The full-budget charge does not go away.** A deployed program can always panic on purpose;
   that arm stays, and it is the correct price for an uncooperative program.
2. **This makes reverts cheaper.** That is what SPECS asks for, but it is a real change in spam
   economics and should be ratified deliberately, not slipped in as an implementation detail.

The one thing I would pull forward regardless of whether the exit-code work is scheduled: the
`Halted(0)` + undecodable-journal path already has exact cycles and throws them away
(`lee/state_machine/src/program/mod.rs:92-98`). That is a standalone bug.
