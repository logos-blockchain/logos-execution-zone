# Sources

## In the repository

- Program interface and execution driver: `lee/state_machine/core/src/program/mod.rs`, `lee/state_machine/core/src/execution_state.rs`.
- Accounts, native token, keys and notes: `lee/state_machine/core/src/{account.rs,native_token.rs,nullifier.rs,commitment.rs,encryption/mod.rs,circuit_io.rs}`.
- Public and private transactions, settlement: `lee/state_machine/src/{public_transaction,privacy_preserving_transaction,validated_state_diff}/`.
- Privacy circuit: `lee/privacy_preserving_circuit/src/`.
- Key protocol and group keys: `lee/key_protocol/src/key_management/`.
- Builtin programs: `lez/programs/*`; program loader: `lez/programs/program_loader/core/src/lib.rs`.
- Fee market and block assembly: `lez/programs/fee/`, `lez/chain_state/src/{apply.rs,classify.rs}`.
- Wallet transaction building: `lez/wallet/src/{lib.rs,account_manager.rs,program_facades/}`.
- Examples and test programs: `examples/program_deployment/`, `test_programs/`, `lee/state_machine/test_methods/guest/src/bin/`.
- Integration tests referenced: `integration_tests/tests/{private_pda.rs,shared_accounts.rs,scoped_reads.rs,native_transfer/private.rs}`.
- Prepared private transactions settling against changed public state: `two_deshielded_transfers_to_one_recipient_compose_at_settlement` and `a_guest_evaluated_public_effect_settles_against_live_state`, both in `lee/state_machine/src/state/tests/privacy_preserving.rs`.
- Tutorials: `docs/LEZ testnet v0.1 tutorials/`.
- The change this book is written against: pull request 912, "incremental updates with restricted program surface", merged into `dev` on 2026-09-25 together with #908 (builtins addressed by stable name), #919 (256-bit private identifiers) and #925 (system program guards).

## Rate-limiting nullifiers

- Logos, [logos-lez-rln](https://github.com/logos-co/logos-lez-rln): the RLN membership registry as a plan/apply program. The [RLN chapter](../catalog/rln.md) is a toy version of it. Read for this book: its README, instruction set, effect types and registration logic. Not read: its Merkle program in full, and the off-chain modules that make and verify the proofs.
- Logos Research, [Rate Limiting Nullifier (RLN)](https://research.logos.co/rln).
- Logos Research, [Strengthening Anonymous DoS Prevention with Rate Limiting Nullifiers in Waku](https://research.logos.co/rlog/rln-anonymous-dos-prevention).
- Waku blog, [Explanation series: RLN Relay](https://blog.waku.org/explanation-series-rln-relay/).
- VAC RFC index, [RLN v1 specification](https://github.com/vacp2p/rfc-index/blob/main/vac/32/rln-v1.md).
- Logos Messaging, [js-rln](https://github.com/logos-messaging/js-rln) and the [RLN v2 contract](https://deepwiki.com/logos-messaging/logos-messaging-rlnv2-contract).
- Status blog, [Rate Limiting Nullifiers explained](https://status.app/blog/rate-limiting-nullifiers-rln-explained) and [Shamir's secret sharing in RLN](https://status.app/blog/shamir-secret-sharing-rln-cryptography).
