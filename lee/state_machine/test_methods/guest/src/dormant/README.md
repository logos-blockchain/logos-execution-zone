Everything here is pulled out of `../bin/` (not auto-discovered by Cargo, not compiled) except
`simple_balance_transfer`, `data_changer`, and `extra_output`, which are fully migrated to
`AccountDiff` and revived.

Two categories:

- `nonce_changer`, `program_owner_changer` — can't be expressed as `AccountDiff`-based programs at
  all: `AccountDiff` has no `nonce`/`program_owner` field, so there's no diff representation of
  what these malicious test programs exist to attempt. See git history for the tests they backed
  (`program_should_fail_if_modifies_nonces`,
  `program_should_fail_if_modifies_program_owner_with_only_non_default_*` in
  `lee/state_machine/src/state/tests/public_program_rules.rs`) — dormant pending a decision on
  whether/how to re-test these invariants now that they're structurally guaranteed rather than
  runtime-checked.
- Everything else — not yet converted. Scope was narrowed to `simple_balance_transfer` to unblock
  a working public-transaction test against `AccountDiff` quickly, and has been growing one
  program at a time since; per-file conversion of the rest (and of the privacy-preserving circuit
  path, `lee/privacy_preserving_circuit`, which has its own, separate blocker) is deferred to a
  later pass.

Reviving a program here requires two things, not just one:
1. Convert its `main()` to the current `AccountDiff`/`AccountDiffOutput` shape, if not already
   done — most files here already are (converted in an earlier mechanical batch pass) even though
   they're still dormant.
2. Switch it from `read_lee_inputs` to `read_lee_call`/`ProgramCall`, matching
   `simple_balance_transfer.rs`/`data_changer.rs`/`extra_output.rs`. This isn't optional: the host
   side (`Program::write_inputs`) now always writes a `CallKind` discriminant first, so any guest
   still reading via `read_lee_inputs` will misinterpret that leading value and read garbage.

`lee/state_machine/src/lib.rs`'s `mod test_methods` wrapper functions and
`with_test_programs()`/`mod` declarations in `lee/state_machine/src/state/tests/mod.rs` are
commented out to match — restore a program here together with its wrapper function, its
`with_test_programs()` registration (if any), and whichever test files reference it.
