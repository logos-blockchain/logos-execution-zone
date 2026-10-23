# Building on the wallet library

`WalletCore` is the Rust client. It holds keys, builds and signs transactions, proves private ones, scans for notes a user can decrypt, and submits. Every runner under `examples/program_deployment/src/bin/` is a sixty-line client built on it, which makes those files the best available worked examples.

Source: `lez/wallet/src/lib.rs`, with account handling in `lez/wallet/src/account_manager.rs`.

## The shape of a client

```rust
let mut wallet_core = WalletCore::from_env()?;

// accounts
let (account_id, _) = wallet_core.create_new_account_public(Some(label));
let nonces = wallet_core.get_accounts_nonces(&[account_id]).await?;
wallet_core.store_persistent_data()?;

// reading
wallet_core.get_account(account_id).await?;
wallet_core.get_account_balance(account_id).await?;
wallet_core.get_account_view(account_id).await?;
wallet_core.get_last_block_id().await?;
wallet_core.get_block(block_id).await?;
wallet_core.get_transaction(tx_hash).await?;

// the mailbox
wallet_core.get_publications().await?;
wallet_core.owned_pending_messages().await?;
wallet_core.find_pending_message(..).await?;

// submitting
wallet_core.send_pub_tx(..).await?;
wallet_core.send_privacy_preserving_tx(accounts, root, message_bytes, &programs).await?;
```

`store_persistent_data` is not optional. Keys created in memory and not stored are lost, which is why the examples' `deploy_program` helper calls it after creating the header and segment accounts.

## Naming an account

This is where most of the library's surface lives, because "which account, and what do we know about it" has nine answers (`AccountIdentity`):

| Variant | Use |
|---|---|
| `Public(id)` | a public account this wallet owns and will sign for |
| `PublicNoSign(id)` | a public account to touch without signing, even if owned |
| `PublicForeign(key)` | someone else's public account, known by key |
| `PublicPda { .. }` | a public program-derived account |
| `PublicKeycard { .. }` | a public account signed by a Keycard; signing mandatory |
| `PrivateOwned(id)` | a private account whose keys and kind the wallet holds |
| `PrivateForeign { .. }` | a private account known only by its public keys: a destination you can send async messages to but cannot witness |
| `PrivateShared { .. }` | a shared regular private account with externally supplied keys, as from a group key |
| `PrivatePdaShared { .. }` | a shared private PDA, likewise |

The distinction that catches people: `PrivateForeign` is a send-only identity. You can address an async message to it, and you cannot produce a witness for it, because witnessing requires the authorization secret key. That asymmetry is the whole reason the mailbox exists ([Private accounts](../build/private-accounts.md)).

Select a program's actor state on an identity before using it:

```rust
let account = AccountIdentity::PrivateOwned(account_id)
    .select_program_actor_state(program_account_id);
```

## Submitting a private transaction

```rust
wallet_core
    .send_privacy_preserving_tx(vec![account], 0, Program::serialize_message(msg)?, &programs)
    .await?;
```

The `programs` argument must list every program the call graph may reach, keyed by deployed account id, each marked disclosed, undisclosed or shadow ([Programs, deployment and identity](../build/programs.md)). A program the execution dispatches to and that was not supplied cannot be proven.

Proving happens in process and takes from tens of seconds to a few minutes depending on the machine and how many handlers run. `RISC0_DEV_MODE=1` skips real proving during development, and must never be used against a real network.

## Deployment from Rust

The examples' helper is the shortest correct deployment, and it differs from the CLI in one way worth knowing: it creates the accounts.

```rust
pub async fn deploy_program(
    wallet_core: &mut WalletCore,
    bytecode: Vec<u8>,
    payer: AccountId,
) -> anyhow::Result<AccountId>
```

It computes `bytecode.len().div_ceil(MAX_SEGMENT_DATA_LEN)`, creates a header account and that many segment accounts, and calls `ProgramLoader(wallet_core).deploy(header, &segments, bytecode, true, Some(payer))`, hardcoding immutable. `wallet program-loader deploy` does none of the account creation, which is why the CLI needs the accounts to exist first.

`payer` must already be funded: a freshly claimed account cannot pay for its own claim.

Source: `examples/program_deployment/src/lib.rs`.

## Where to start reading

`run_hello_world.rs` is the minimal public client. `run_hello_world_private.rs` is the same thing privately, and the diff between them is the clearest statement of what changes on the client side when an account is private, which is: the account identity, and nothing else.
