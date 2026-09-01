use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee_core::{account::AccountId, program::PROGRAM_LOADER_ACCOUNT_ID};
use log::info;
use sequencer_core::{
    block_publisher::{Ed25519PublicKey, read_channel_state},
    config::BedrockConfig,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, verify_commitment_is_in_state};
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
/// Maximum time a single [`wait_until`] may poll before giving up.
const PHASE_TIMEOUT: Duration = Duration::from_secs(360);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Polls `check` until it reports ready, failing with `what` on timeout.
pub async fn wait_until<F, Fut>(what: &str, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let wait = async {
        while !check().await? {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(PHASE_TIMEOUT, wait)
        .await
        .with_context(|| format!("Timed out waiting for {what}"))?
}

/// The channel's accredited keys, sorted, plus whose turn the tip was written on.
pub async fn committee(
    config: &BedrockConfig,
) -> Result<(Vec<[u8; 32]>, Option<Ed25519PublicKey>)> {
    let Some(state) = read_channel_state(config).await? else {
        return Ok((Vec::new(), None));
    };
    let turn = state
        .accredited_keys
        .get(usize::from(state.tip_sequencer))
        .copied();
    let mut keys: Vec<_> = state
        .accredited_keys
        .iter()
        .map(Ed25519PublicKey::to_bytes)
        .collect();
    keys.sort_unstable();
    Ok((keys, turn))
}

/// Asserts A and B hold byte-identical block hashes over their common prefix.
pub async fn assert_same_chain(a: &SequencerClient, b: &SequencerClient) -> Result<()> {
    let common = a
        .get_last_block_id()
        .await?
        .min(b.get_last_block_id().await?);
    for id in 1..=common {
        let block_a = a
            .get_block(id)
            .await?
            .with_context(|| format!("A is missing block {id}"))?;
        let block_b = b
            .get_block(id)
            .await?
            .with_context(|| format!("B is missing block {id}"))?;
        ensure!(
            block_a.header.hash == block_b.header.hash,
            "Chain divergence at block {id}: A {:?} vs B {:?}",
            block_a.header.hash,
            block_b.header.hash
        );
    }
    Ok(())
}

/// Create a private or public account at the given chain index and return its ID.
/// Pass `cci: None` to use the wallet's next available chain index.
pub async fn new_account(
    ctx: &mut TestContext,
    private: bool,
    cci: Option<ChainIndex>,
) -> anyhow::Result<AccountId> {
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
) -> anyhow::Result<()> {
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
) -> anyhow::Result<()> {
    NativeTokenTransfer(ctx.wallet())
        .send_public_transfer(
            AccountIdentity::Public(from),
            AccountIdentity::Public(to),
            amount,
        )
        .await?;
    info!("Waiting for next block creation");
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
) -> anyhow::Result<()> {
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id,
        supply_account_id,
        name: name.into(),
        total_supply,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Send tokens and wait for the block to be included.
pub async fn token_send(
    ctx: &mut TestContext,
    from: CliAccountMention,
    to: CliAccountMention,
    amount: u128,
) -> anyhow::Result<()> {
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
    info!("Waiting for next block creation");
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
) -> anyhow::Result<()> {
    Token(ctx.wallet())
        .send_transfer_transaction(
            AccountIdentity::Public(from),
            AccountIdentity::Public(to),
            amount,
        )
        .await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Retrieve the native token balance for `account_id`.
pub async fn account_balance(ctx: &TestContext, account_id: AccountId) -> anyhow::Result<u128> {
    Ok(ctx
        .sequencer_client()
        .get_account_balance(account_id)
        .await?)
}

/// Fetch the full account state for `account_id` from the sequencer.
pub async fn get_account(ctx: &TestContext, account_id: AccountId) -> anyhow::Result<lee::Account> {
    Ok(ctx.sequencer_client().get_account(account_id).await?)
}

/// Fetch the current commitment for `account_id` and assert it is present in the sequencer state.
pub async fn assert_private_commitment_in_state(
    ctx: &TestContext,
    account_id: AccountId,
    label: &str,
) -> anyhow::Result<()> {
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(account_id)
        .with_context(|| format!("Failed to get commitment for {label}"))?;
    assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    Ok(())
}

/// Sync the wallet's private accounts.
pub async fn sync_private(ctx: &mut TestContext) -> anyhow::Result<()> {
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
pub async fn wait_for_indexer_to_catch_up(ctx: &TestContext) -> anyhow::Result<u64> {
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
                info!(
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

/// Builds the transaction that uploads `bytecode` as a single new segment, signed by `key`.
/// Returns the segment's `AccountId` and the transaction. Useful on its own for tests that only
/// care about transaction size/shape, not about invoking the deployed program afterward.
#[must_use]
pub fn new_segment_transaction(
    bytecode: Vec<u8>,
    key: &lee::PrivateKey,
) -> (AccountId, lee::PublicTransaction) {
    let segment = AccountId::from(&lee::PublicKey::new_from_private_key(key));
    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        vec![segment],
        vec![lee_core::account::Nonce(0)],
        program_loader_core::Instruction::WriteSegment {
            bytecode,
            next_segment: None,
        },
    )
    .expect("NewSegment instruction data should always be serializable");
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[key]);
    (segment, lee::PublicTransaction::new(message, witness_set))
}

/// Uploads `bytecode` as a chunked, tail-to-head segment chain, one signed `NewSegment` tx per
/// chunk, in submission order. Segment keys are `[key_seed + i; 32]`; pick seeds with enough
/// headroom to avoid collisions. Returns segment `AccountId`s (first to last) and their txs.
#[must_use]
pub fn segment_upload_transactions(
    bytecode: &[u8],
    key_seed: u8,
) -> (Vec<AccountId>, Vec<lee::PublicTransaction>) {
    let chunks: Vec<&[u8]> = bytecode
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    assert!(!chunks.is_empty(), "bytecode must not be empty");

    let segment_keys: Vec<lee::PrivateKey> = (0..chunks.len())
        .map(|i| {
            let seed = key_seed
                .checked_add(u8::try_from(i).expect("chunk count fits in a u8"))
                .expect("key_seed left enough headroom for every chunk");
            lee::PrivateKey::try_new([seed; 32]).unwrap()
        })
        .collect();
    let segment_ids: Vec<AccountId> = segment_keys
        .iter()
        .map(|key| AccountId::from(&lee::PublicKey::new_from_private_key(key)))
        .collect();

    let mut txs = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate().rev() {
        let next_segment = segment_ids.get(i + 1).copied();
        let mut account_ids = vec![segment_ids[i]];
        account_ids.extend(next_segment);
        let message = lee::public_transaction::Message::try_new(
            PROGRAM_LOADER_ACCOUNT_ID,
            account_ids,
            vec![lee_core::account::Nonce(0)],
            program_loader_core::Instruction::WriteSegment {
                bytecode: (*chunk).to_vec(),
                next_segment,
            },
        )
        .expect("NewSegment instruction data should always be serializable");
        let witness_set =
            lee::public_transaction::WitnessSet::for_message(&message, &[&segment_keys[i]]);
        txs.push(lee::PublicTransaction::new(message, witness_set));
    }
    (segment_ids, txs)
}

/// Builds the `UploadHeader` transaction for a chain already uploaded via
/// [`segment_upload_transactions`], signed by `header_key`.
#[must_use]
pub fn upload_header_transaction(
    all_segment_ids: &[AccountId],
    header_key: &lee::PrivateKey,
) -> (AccountId, lee::PublicTransaction) {
    let header = AccountId::from(&lee::PublicKey::new_from_private_key(header_key));
    let mut account_ids = vec![header];
    account_ids.extend_from_slice(all_segment_ids);
    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        account_ids,
        vec![lee_core::account::Nonce(0)],
        program_loader_core::Instruction::CreateHeader {
            first_segment: all_segment_ids[0],
            immutable: true,
        },
    )
    .expect("UploadHeader instruction data should always be serializable");
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[header_key]);
    (header, lee::PublicTransaction::new(message, witness_set))
}

/// Every transaction needed to deploy `bytecode` for real: its full segment chain (see
/// [`segment_upload_transactions`]) followed by the `UploadHeader`, in submission order. All must
/// land in a block, in order, before the program is invocable at the returned header `AccountId`.
#[must_use]
pub fn deploy_program_transactions(
    bytecode: &[u8],
    key_seed: u8,
    header_key: &lee::PrivateKey,
) -> (AccountId, Vec<lee::PublicTransaction>) {
    let (segment_ids, mut txs) = segment_upload_transactions(bytecode, key_seed);
    let (header, header_tx) = upload_header_transaction(&segment_ids, header_key);
    txs.push(header_tx);
    (header, txs)
}

/// The exact wire size the sequencer measures a transaction by (see
/// `sequencer_rpc_server_actor::actor::service`'s `send_transaction`).
#[must_use]
pub fn encoded_tx_size(tx: &common::transaction::LeeTransaction) -> u64 {
    u64::try_from(
        borsh::to_vec(tx)
            .expect("transaction should serialize")
            .len(),
    )
    .expect("transaction size should fit in u64")
}
