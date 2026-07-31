Everything here is pulled out of `../bin/` (not auto-discovered by Cargo, not compiled) except
`simple_balance_transfer`, which is the one program fully migrated to `AccountDiff` so far.

Two categories:

- `nonce_changer`, `program_owner_changer` — can't be expressed as `AccountDiff`-based programs at
  all: `AccountDiff` has no `nonce`/`program_owner` field, so there's no diff representation of
  what these malicious test programs exist to attempt. See git history for the tests they backed
  (`program_should_fail_if_modifies_nonces`,
  `program_should_fail_if_modifies_program_owner_with_only_non_default_*` in
  `lee/state_machine/src/state/tests/public_program_rules.rs`) — dormant pending a decision on
  whether/how to re-test these invariants now that they're structurally guaranteed rather than
  runtime-checked.
- Everything else — not yet converted. Scope was narrowed to just `simple_balance_transfer` to
  unblock a working public-transaction test against `AccountDiff` quickly, per-file conversion of
  the rest (and of the privacy-preserving circuit path, `lee/privacy_preserving_circuit`, which has
  its own, separate blocker) deferred to a later pass.

`lee/state_machine/src/lib.rs`'s `mod test_methods` wrapper functions and
`with_test_programs()`/`mod` declarations in `lee/state_machine/src/state/tests/mod.rs` are
commented out to match — restore a program here together with its wrapper function, its
`with_test_programs()` registration (if any), and whichever test files reference it.
