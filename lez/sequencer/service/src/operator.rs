//! The `setup`, `stake` and `unstake` commands.
#![expect(
    clippy::print_stdout,
    reason = "these commands report to the operator on stdout"
)]

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use lee::{AccountId, ProgramShardSelector, program::Program};
use sequencer_core::config::GenesisAction;
use sequencer_service::SequencerConfig;
use sequencer_stake_core::{Instruction, SequencerKey, SequencerStakeConfig};
use wallet::{AccountIdentity, WalletCore, account::AccountIdWithPrivacy, cli::CliAccountMention};

/// The node's config, read by `start`.
pub const CONFIG_FILE: &str = "sequencer_config.json";

/// Creates `home` with its config, channel signing key and Bedrock funding public key.
pub fn setup(
    home: &Path,
    template: &Path,
    funding_public_key: &str,
    create_channel: bool,
) -> Result<()> {
    ensure!(
        !home.join(CONFIG_FILE).exists(),
        "{} is already set up",
        home.display()
    );
    sequencer_core::parse_funding_public_key(funding_public_key)
        .context("Invalid --funding-public-key")?;
    std::fs::create_dir_all(home)
        .with_context(|| format!("Failed to create {}", home.display()))?;
    let home = home
        .canonicalize()
        .with_context(|| format!("Failed to resolve {}", home.display()))?;

    // Not `SequencerConfig::from_path`: its genesis checks don't apply to a joiner, who drops it.
    let template_file = std::fs::File::open(template)
        .with_context(|| format!("Failed to open the config at {}", template.display()))?;
    let mut config: SequencerConfig =
        serde_json::from_reader(std::io::BufReader::new(template_file))
            .with_context(|| format!("Failed to read the config at {}", template.display()))?;
    config.home.clone_from(&home);
    if create_channel {
        let genesis = config
            .genesis
            .as_ref()
            .context("--create-channel needs a config with a `genesis`")?;
        sequencer_core::config::check_channel_params(
            &genesis.channel_params,
            config.block_create_timeout,
        )?;
    } else {
        // Without it, a node pointed at the wrong channel fails instead of creating that one.
        config.genesis = None;
    }
    // An existing key is kept: it may already be staked.
    let channel_key = sequencer_core::load_or_create_signing_key(
        &home.join(sequencer_core::CHANNEL_SIGNING_KEY_FILE),
    )?;
    std::fs::write(
        home.join(sequencer_core::BEDROCK_FUNDING_PUBLIC_KEY_FILE),
        funding_public_key.trim(),
    )
    .context("Failed to write the funding public key")?;
    let config_json =
        serde_json::to_string_pretty(&config).context("Failed to serialize the config")?;
    std::fs::write(home.join(CONFIG_FILE), config_json).context("Failed to write the config")?;

    println!("{} is set up", home.display());
    println!(
        "  channel signing public key  {}",
        hex::encode(channel_key.public_key().to_bytes())
    );
    // Creating the channel self-stakes the key unless the genesis lists founding stakes.
    let own_key = SequencerKey::new(channel_key.public_key().to_bytes());
    let staked_at_genesis = create_channel
        && config.genesis.as_ref().is_some_and(|genesis| {
            let founding: Vec<_> = genesis
                .actions
                .iter()
                .filter_map(|action| match action {
                    GenesisAction::StakeSequencer { sequencer_key, .. } => Some(*sequencer_key),
                    GenesisAction::SupplyAccount { .. }
                    | GenesisAction::SupplyBridgeLockHolding { .. } => None,
                })
                .collect();
            founding.is_empty() || own_key.is_some_and(|key| founding.contains(&key))
        });
    if create_channel {
        println!("`start` creates the channel if it does not exist yet.");
    }
    if staked_at_genesis {
        println!("Creating the channel stakes that key at genesis.");
    } else {
        println!("Pass that key to `stake --sequencer-key`.");
    }
    Ok(())
}

/// Parses the hex channel signing public key a stake accredits.
pub fn parse_sequencer_key(hex_key: &str) -> Result<SequencerKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim_start_matches("0x"))
        .context("not hex")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("{} bytes, expected 32", bytes.len()))?;
    SequencerKey::new(bytes).context("not a valid ed25519 public key")
}

/// Stakes `key` from `from`, by default the minimum.
pub async fn stake(
    wallet_home: Option<PathBuf>,
    key: SequencerKey,
    from: CliAccountMention,
    amount: Option<u128>,
) -> Result<()> {
    let mut wallet = open_wallet(wallet_home)?;
    let funding = public_account(&wallet, &from)?;
    let config = stake_config(&wallet).await?;
    let minimum = minimum_stake(&config)?;

    if let Some(entry) = config.entries.get(&key) {
        bail!(
            "This channel signing key is already staked ({})",
            entry.net_stake()
        );
    }
    let amount = amount.unwrap_or(minimum);
    ensure!(
        amount >= minimum,
        "A stake must be at least the minimum of {minimum}"
    );
    let balance = wallet.get_account_balance(funding).await?;
    ensure!(
        balance >= amount,
        "{funding} holds {balance}, short of the {amount} to stake"
    );
    let (ownership, _) = wallet.create_new_account_public(None);
    wallet.store_persistent_data()?;

    let program_id = programs::sequencer_stake_account_id();
    let instruction = Program::serialize_instruction(Instruction::Stake {
        sequencer_key: key,
        amount,
        has_record: false,
    })
    .context("Failed to serialize the Stake instruction")?;
    let tx_hash = wallet
        .send_pub_tx(
            vec![
                from.into_public_identity(funding, true).balance(),
                AccountIdentity::Public(ownership).select_program_shard(program_id),
                AccountIdentity::PublicNoSign(system_accounts::stake_funds_account_id(&ownership))
                    .balance(),
                AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id())
                    .select_program_shard(program_id),
            ],
            instruction,
            program_id,
        )
        .await
        .map_err(|err| anyhow!("Failed to submit the Stake transaction: {err:?}"))?;
    println!("Staking {amount} from {funding} into {ownership}: {tx_hash}");
    confirm(&wallet, tx_hash).await
}

/// Requests the release of `key`'s stake to `destination`, by default all of it.
pub async fn unstake(
    wallet_home: Option<PathBuf>,
    key: SequencerKey,
    destination: CliAccountMention,
    amount: Option<u128>,
) -> Result<()> {
    let wallet = open_wallet(wallet_home)?;
    let destination = public_account(&wallet, &destination)?;
    let config = stake_config(&wallet).await?;
    let minimum = minimum_stake(&config)?;
    let entry = config
        .entries
        .get(&key)
        .context("This channel signing key has no stake")?;

    ensure!(
        entry.total_pending_unstake == 0,
        "An unstake request is already pending"
    );
    let amount = amount.unwrap_or_else(|| entry.net_stake());
    ensure!(amount > 0, "Nothing staked to release");
    let remaining = entry
        .net_stake()
        .checked_sub(amount)
        .with_context(|| format!("Only {} is staked", entry.net_stake()))?;
    ensure!(
        remaining == 0 || remaining >= minimum,
        "Releasing {amount} would leave {remaining}, under the minimum of {minimum}"
    );
    // The wallet drops a signature it holds no key for without saying so.
    ensure!(
        wallet
            .get_account_public_signing_key(entry.account_id)
            .is_some(),
        "The wallet holds no key for the stake's ownership account {}; import it with `wallet \
         account import public`",
        entry.account_id
    );

    let requested_at = wallet
        .get_last_block_id()
        .await
        .context("Failed to read the chain height")?
        .saturating_add(sequencer_stake_core::UNSTAKE_REQUEST_WINDOW);
    let program_id = programs::sequencer_stake_account_id();
    let instruction = Program::serialize_instruction(Instruction::UnstakeRequest {
        sequencer_key: key,
        amount,
        destination,
        requested_at,
    })
    .context("Failed to serialize the UnstakeRequest instruction")?;
    let tx_hash = wallet
        .send_pub_tx(
            vec![
                AccountIdentity::Public(entry.account_id).select_program_shard(program_id),
                AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id())
                    .select_program_shard(program_id),
            ],
            instruction,
            program_id,
        )
        .await
        .map_err(|err| anyhow!("Failed to submit the UnstakeRequest transaction: {err:?}"))?;
    println!("Releasing {amount} to {destination}: {tx_hash}");
    confirm(&wallet, tx_hash).await
}

fn open_wallet(home: Option<PathBuf>) -> Result<WalletCore> {
    let home = match home {
        Some(home) => home,
        None => wallet::helperfunctions::get_home()?,
    };
    WalletCore::new_update_chain(
        home.join("wallet_config.json"),
        home.join("storage.json"),
        None,
    )
    .with_context(|| format!("Failed to open the wallet in {}", home.display()))
}

fn public_account(wallet: &WalletCore, mention: &CliAccountMention) -> Result<AccountId> {
    match mention.resolve(wallet.storage())? {
        AccountIdWithPrivacy::Public(account) => Ok(account),
        AccountIdWithPrivacy::Private(_) => bail!("{mention} is private; stakes move public funds"),
    }
}

async fn stake_config(wallet: &WalletCore) -> Result<SequencerStakeConfig> {
    let program_id = programs::sequencer_stake_account_id();
    let account = wallet
        .get_account_view(ProgramShardSelector::new(
            system_accounts::sequencer_stake_config_account_id(),
            program_id,
        ))
        .await
        .context("Failed to read the stake config")?;
    SequencerStakeConfig::from_bytes(account.data.shard(program_id).as_ref())
        .context("Failed to decode the stake config")
}

fn minimum_stake(config: &SequencerStakeConfig) -> Result<u128> {
    Ok(config
        .channel_params
        .context("The stake config has no channel params")?
        .minimum_sequencer_stake)
}

async fn confirm(wallet: &WalletCore, tx_hash: common::HashType) -> Result<()> {
    let (_, block_id) = wallet
        .poll_transaction(tx_hash)
        .await
        .context("The transaction did not show up in a block")?;
    println!("Included in block {block_id}");
    Ok(())
}
