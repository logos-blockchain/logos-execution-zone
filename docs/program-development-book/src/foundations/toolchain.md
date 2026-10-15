# Toolchain: build, deploy, test

## Prerequisites

Rust (the workspace pins a toolchain in `rust-toolchain.toml`), the RISC Zero toolchain (`rzup install`), and a running sequencer for anything that submits transactions. The repository `README.md` covers installation and how to run a local sequencer; the tutorials under `docs/LEZ testnet v0.1 tutorials/` cover wallet setup.

## A program crate

The smallest working layout is `examples/program_deployment/methods/guest/`:

```toml
# methods/guest/Cargo.toml
[package]
name = "example_program_deployment_programs"
edition = "2024"

[dependencies]
borsh = { workspace = true }
lee_core = { workspace = true }
risc0-zkvm = { workspace = true }   # keeps the guest runtime linked
```

with one `src/bin/<program>.rs` per program:

```rust
use lee_core::program::{run_program, Plan, PlanInput};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect { Append(Vec<u8>) }

fn plan(input: &PlanInput, bytes: Vec<u8>) -> Plan {
    let [account] = input.accounts.as_slice() else { panic!("one account") };
    let mut plan = Plan::new(input);
    plan.effect(account, &Effect::Append(bytes));
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    let Effect::Append(bytes) = effect;
    let mut out = pre_data.to_vec();
    out.extend(bytes);
    Some(out)
}

fn main() { run_program(plan, apply) }
```

Build reproducibly with the RISC Zero Docker builder:

```bash
cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
# artifacts land in target/riscv32im-risc0-zkvm-elf/docker/<program>.bin
```

The builtin programs are built the same way through `lez/programs` (`just build-artifacts`), and their `.bin` files are committed under `artifacts/`. Tests that embed guests use `risc0_build::embed_methods()` in a `build.rs` instead (see `test_programs/`); that build is not reproducible but needs no Docker.

## Deploying

```bash
wallet account new public --label my-program-header
wallet account new public --label my-program-seg-0   # and seg-1, seg-2, ...
wallet program-loader deploy \
  --elf target/riscv32im-risc0-zkvm-elf/docker/my_program.bin \
  --header my-program-header \
  --segments my-program-seg-0 my-program-seg-1 my-program-seg-2 \
  --immutable
```

The header and every segment account must exist already, with an empty `program_loader` shard: the wallet chunks the ELF but never creates accounts. You need one segment account per `MAX_SEGMENT_DATA_LEN` = 96 KiB of the user ELF, so a typical program takes several; if the count is wrong the deploy fails with `SegmentCountMismatch`, which reports the number expected. A deploy that fails partway cannot currently be resumed over the same accounts, so retry with fresh ones. `deploy` prints the header account id, which is the program's account id from then on. From Rust, `program_deployment::deploy_program(&mut wallet, bytecode, payer)` does the same and returns the id; `ProgramLoader(&wallet).deploy(header, &segments, bytecode, immutable, payer)` gives full control. Deploy with `immutable: true` unless you have a reason not to; it is required for undisclosed use and it is what users will expect.

Callers need the program's account id. Programs that chain into yours need it too, and they cannot hardcode it before you deploy, so pass it in instruction data or store it in a config PDA written at genesis or by the deployer (the pattern `bridge_lock::InitConfig` uses).

## Invoking

Public, by hand: build a `Message`, sign with `WitnessSet::for_message`, wrap in `PublicTransaction`, submit with the RPC client's `send_transaction`. The runners in `examples/program_deployment/src/bin/` do this in fifty lines each.

Private: `wallet_core.send_privacy_preserving_tx(accounts, instruction_bytes, &program_with_dependencies)`. The wallet resolves each `AccountIdentity` into selectors, witnesses and signers, proves, and submits. `ProgramWithDependencies::new(program, program_account_id, dependencies)` must list every program the call graph may reach, keyed by deployed account id.

Reading state: `wallet account get --scope <balance|all|<program account id>> --account-id Public/<id>` (default `balance`) and, after `wallet account sync-private`, the same for `Private/<id>`. Prefer scoped reads: a whole-account read can exceed the response limit once an account has accumulated large shards (`integration_tests/tests/scoped_reads.rs`).

## Testing

**Unit tests, no zkVM.** `plan` and `apply` are ordinary functions. Build a `PlanInput` with `AccountMeta`s, call `plan`, and assert on `plan.output().effects` and `.chained_calls`; call `apply` on hand-made shard bytes and use `#[should_panic(expected = "...")]` for guards. Every builtin has such tests next to its code (the `mod tests` blocks in each `main.rs`; `logos-blockchain/lez-programs: programs/amm/src/tests.rs` is a larger worked set). This is where most of your coverage should live.

**State tests, executor only.** `V03State::new().with_named_programs([(program_account_id, program)]).with_public_account_balances(..)` (or `with_programs([program])`, which seeds at the test-only `from_builtin_program` address) then `transition_from_public_transaction(&tx, block_id, timestamp)` runs the real dispatch loop with the RISC Zero executor (no proof). Tests in `lee/state_machine/src/state/tests/` cover chained calls, PDAs, validity windows, flash swaps and the error paths, and are a good template.

**Proof tests.** `execute_and_prove(ProvingInput{..}, &program_with_dependencies)` followed by `ValidatedStateDiff::from_privacy_preserving_transaction` exercises the circuit end to end. They are slow (minutes) and are plain `#[test]`, not feature-gated; the `prove` feature swaps the executor implementation, and `RISC0_DEV_MODE=1` is what makes them cheap. Keep a few, not many.

**Integration tests.** `integration_tests/` spins up a sequencer and a wallet (`TestContext`) and drives the CLI or `WalletCore`. `private_pda.rs` and `shared_accounts.rs` are the ones to read for private flows.

## Debugging

A guest panic surfaces as `ProgramExecutionFailed("Guest panicked: <message>")` in the sequencer log for public transactions, and as a local error from `execute_and_prove` for private ones. Write panic messages that name the check. `env::log` prints to the host's debug console from inside the guest; it is always compiled, not development-only. Cycle counts are reported per call by the executor and are what you pay for in public transactions; the `tools/cycle_bench` crate measures them.

## Versioning your shard layout

Shard bytes are the only persistent thing and every future version of your program must read what past versions wrote. Borsh enums are append-only (a new variant goes last); domain-separate seeds with a version string (`b"/MYAPP/v1/..."`); and remember that redeploying at a new account id gives you fresh shards and fresh PDAs but strands everything under the old id.
