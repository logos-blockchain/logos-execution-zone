Programs here are excluded from the build (this directory isn't auto-discovered by Cargo's
`src/bin/*.rs` bin scanning, unlike `../bin/`).

They tested attacks that are no longer expressible, or no longer meaningful, once program
outputs are diff-native (`AccountDiff`/`AccountDiffOutput`):

- `nonce_changer`, `program_owner_changer`: `AccountDiff` has no `nonce` or `program_owner`
  field, so a program has no channel left to change either. The corresponding
  `ExecutionValidationError` variants they asserted on (`ModifiedNonce`, `ModifiedProgramOwner`)
  have been removed.
- `modified_transfer`: relied on a malicious program skipping its own balance check and letting
  protocol-level total-balance conservation catch the resulting overflow
  (`MismatchedTotalBalance`). `apply_balance_diff` now applies checked arithmetic to every
  `AccountDiff` unconditionally, so the same attack is now rejected earlier, by a different and
  simpler mechanism (`BalanceDiffError`), regardless of which program produced the diff — this
  program no longer demonstrates anything specific to itself.
