//! Integration test helpers, re-exported from `test_fixtures` for backwards
//! compatibility. The actual fixtures live in the `test_fixtures` crate so that
//! non-test consumers (e.g. `integration_bench`) can depend on them without
//! pulling in the test files.

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::{
    AccountId,
    public_transaction::{Message, WitnessSet},
};
use lee_core::program::{ProgramId, RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID};
use sequencer_service_rpc::RpcClient as _;
pub use test_fixtures::*;
use wallet::{
    AccountIdentity,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        programs::{
            native_token_transfer::AuthTransferSubcommand, token::TokenProgramAgnosticSubcommand,
        },
    },
    program_facades::{native_token_transfer::NativeTokenTransfer, token::Token},
    storage::key_chain::FoundPrivateAccount,
};

/// Maximum time to wait for the indexer to catch up to the sequencer.
pub const L2_TO_L1_TIMEOUT: Duration = Duration::from_mins(6);

/// Derives the `(header, segments)` accounts `bytecode` would deploy to via `Deploy`, mirroring
/// `sequencer_core`'s private test helper of the same name.
#[must_use]
pub fn deploy_targets(bytecode: &[u8]) -> (AccountId, Vec<AccountId>) {
    let loader_id: ProgramId = RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID.into();
    let user_elf = loader_core::extract_user_elf(bytecode).unwrap();
    let image_id = loader_core::compute_image_id(&user_elf).unwrap();
    let plan = loader_core::plan_deploy(loader_id, image_id, AccountId::default(), &user_elf);
    (
        plan.header.account_id,
        plan.segments.into_iter().map(|s| s.account_id).collect(),
    )
}

/// Builds the `PublicTransaction` that deploys `bytecode` to `(header, segments)`.
///
/// `(header, segments)` are the targets [`deploy_targets`] derives for it. `bytecode` is the full
/// two-ELF `Program::elf()` blob; this extracts just the `user_elf` for the wire payload, mirroring
/// what `execute_deploy` expects. Tests should invoke programs at the returned `header` address
/// afterward, not the program's own bijection `AccountId::from(image_id)`.
#[must_use]
pub fn deploy_transaction(
    header: AccountId,
    segments: &[AccountId],
    bytecode: &[u8],
) -> lee::PublicTransaction {
    let loader_id: ProgramId = RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID.into();
    // Falls back to sending `bytecode` through unmodified when it isn't a well-formed two-ELF
    // `ProgramBinary` (e.g. deliberately-garbage test input) — extraction is best-effort here so
    // malformed input still reaches `execute_deploy`'s own rejection path, rather than this
    // helper itself panicking before the real system ever sees it.
    let user_elf = loader_core::extract_user_elf(bytecode).unwrap_or_else(|_| bytecode.to_vec());
    let mut account_ids = vec![header];
    account_ids.extend_from_slice(segments);
    let message = Message::try_new(
        loader_id.into(),
        account_ids,
        vec![],
        loader_core::Instruction::Deploy {
            update_auth: AccountId::default(),
        },
    )
    .expect("deploy instruction data should always be serializable")
    .with_raw_payload(user_elf);
    let witness_set = WitnessSet::for_message(&message, &[]);
    lee::PublicTransaction::new(message, witness_set)
}

/// The exact wire size the sequencer measures a transaction by.
///
/// See `sequencer_rpc_server_actor::actor::service`'s `send_transaction`. Measuring the real
/// encoded size here (rather than assuming it from bytecode length) keeps size-sensitive tests
/// correct regardless of borsh/transaction encoding overhead.
#[must_use]
pub fn encoded_tx_size(tx: &LeeTransaction) -> u64 {
    u64::try_from(
        borsh::to_vec(tx)
            .expect("transaction should serialize")
            .len(),
    )
    .expect("transaction size should fit in u64")
}

/// Create a private or public account at the given chain index and return its ID.
/// Pass `cci: None` to use the wallet's next available chain index.
pub async fn new_account(
    ctx: &mut TestContext,
    private: bool,
    cci: Option<ChainIndex>,
) -> Result<AccountId> {
    let subcommand = if private {
        NewSubcommand::Private { cci, label: None }
    } else {
        NewSubcommand::Public { cci, label: None }
    };
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(subcommand)),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };
    Ok(account_id)
}

/// Send `amount` from `from` to `to` via an authenticated transfer (identifier 0).
pub async fn send(
    ctx: &mut TestContext,
    from: CliAccountMention,
    to: CliAccountMention,
    amount: u128,
) -> Result<()> {
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from,
        to: Some(to),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    Ok(())
}

/// Like [`send`], but for a `to` that is still a fresh, unclaimed account.
///
/// The wallet CLI's `AuthTransfer::Send` never signs with the recipient's key (by design: the
/// sender's wallet must not sign on behalf of an account it doesn't own). But claiming a fresh
/// account is only possible if that account's own key signs the transaction, so this bypasses
/// the CLI and calls the program facade directly with an explicit `AccountIdentity::Public` for
/// the recipient, using the key the test wallet holds for the account it just created.
///
/// Unlike `send`, this doesn't go through the CLI's own poll-until-included step, so it waits
/// for block creation itself before returning.
pub async fn send_claiming_new_account(
    ctx: &mut TestContext,
    from: AccountId,
    to: AccountId,
    amount: u128,
) -> Result<()> {
    NativeTokenTransfer(ctx.wallet())
        .send_public_transfer(
            AccountIdentity::Public(from),
            AccountIdentity::Public(to),
            amount,
        )
        .await?;
    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Create a token (New) and wait for the block to be included.
pub async fn create_token(
    ctx: &mut TestContext,
    definition_account_id: CliAccountMention,
    supply_account_id: CliAccountMention,
    name: impl Into<String>,
    total_supply: u128,
) -> Result<()> {
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id,
        supply_account_id,
        name: name.into(),
        total_supply,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Send tokens and wait for the block to be included.
pub async fn token_send(
    ctx: &mut TestContext,
    from: CliAccountMention,
    to: CliAccountMention,
    amount: u128,
) -> Result<()> {
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from,
        to: Some(to),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Like [`token_send`], but for a `to` that is still a fresh, unclaimed holding account. See
/// [`send_claiming_new_account`] for why the CLI can't be used here.
pub async fn token_send_claiming_new_account(
    ctx: &mut TestContext,
    from: AccountId,
    to: AccountId,
    amount: u128,
) -> Result<()> {
    Token(ctx.wallet())
        .send_transfer_transaction(
            AccountIdentity::Public(from),
            AccountIdentity::Public(to),
            amount,
        )
        .await?;
    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Retrieve the native token balance for `account_id`.
pub async fn account_balance(ctx: &TestContext, account_id: AccountId) -> Result<u128> {
    Ok(ctx
        .sequencer_client()
        .get_account_balance(account_id)
        .await?)
}

/// Fetch the full account state for `account_id` from the sequencer.
pub async fn get_account(ctx: &TestContext, account_id: AccountId) -> Result<lee::Account> {
    Ok(ctx.sequencer_client().get_account(account_id).await?)
}

/// Fetch the current commitment for `account_id` and assert it is present in the sequencer state.
pub async fn assert_private_commitment_in_state(
    ctx: &TestContext,
    account_id: AccountId,
    label: &str,
) -> Result<()> {
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(account_id)
        .with_context(|| format!("Failed to get commitment for {label}"))?;
    assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    Ok(())
}

/// Sync the wallet's private accounts.
pub async fn sync_private(ctx: &mut TestContext) -> Result<()> {
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::SyncPrivate {}),
    )
    .await?;
    Ok(())
}

/// Look up a restored private account for `account_id`, panicking with `label` if absent.
#[must_use]
pub fn restored_private_account<'ctx>(
    ctx: &'ctx TestContext,
    account_id: AccountId,
    label: &str,
) -> FoundPrivateAccount<'ctx> {
    ctx.wallet()
        .storage()
        .key_chain()
        .private_account(account_id)
        .unwrap_or_else(|| panic!("{label} should be restored"))
}

/// Assert that a restored public account's signing key exists, panicking with `label` if absent.
pub fn assert_public_account_restored(ctx: &TestContext, account_id: AccountId, label: &str) {
    ctx.wallet()
        .storage()
        .key_chain()
        .pub_account_signing_key(account_id)
        .unwrap_or_else(|| panic!("{label} should be restored"));
}

/// Poll the indexer until its last finalized block id reaches the sequencer's
/// current last block id or until [`L2_TO_L1_TIMEOUT`] elapses.
/// Returns the last indexer block id observed.
pub async fn wait_for_indexer_to_catch_up(ctx: &TestContext) -> Result<u64> {
    use indexer_service_rpc::RpcClient as _;

    let block_id_to_catch_up =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;
    let mut last_ind: u64 = 1;
    let inner = async {
        loop {
            let ind = ctx
                .indexer_client()
                .get_last_finalized_block_id()
                .await?
                .unwrap_or(0);
            last_ind = ind;
            if ind >= block_id_to_catch_up {
                let last_seq =
                    sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client())
                        .await?;
                log::info!(
                    "Indexer caught up. Indexer last block id: {ind}. Current sequencer last block id: {last_seq}"
                );
                return Ok(ind);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::time::timeout(L2_TO_L1_TIMEOUT, inner)
        .await
        .with_context(|| {
            format!(
                "Indexer failed to catch up within {L2_TO_L1_TIMEOUT:?}. Last indexer block id observed: {last_ind}, but needed to catch up to at least {block_id_to_catch_up}"
            )
        })?
}
