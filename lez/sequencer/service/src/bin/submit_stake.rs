//! Submits `Stake`/`UnstakeRequest` transactions for the self-join flow,
//! signed with keys already held by a wallet at the given path.
//!
//! For `stake`, the funding account must already be owned by
//! `authenticated_transfer` and hold at least `amount`. The ownership account
//! should be fresh (or already backing the same sequencer key). Both must
//! already exist in the wallet (e.g. via `wallet account new public`).

use anyhow::{Context as _, Result, anyhow};
use clap::{Parser, Subcommand};
use lee::{AccountId, program::Program};
use wallet::{AccountIdentity, WalletCore};

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    /// Path to the wallet's home directory (holds `wallet_config.json`,
    /// `storage.json` and `statistics.json`).
    #[clap(long)]
    wallet: std::path::PathBuf,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Locks `amount` into a stake ownership account for `sequencer_key`.
    Stake {
        /// Account funding the stake; must already be authenticated_transfer-owned.
        #[clap(long)]
        funding_account: AccountId,
        /// Stake ownership account for `sequencer_key`.
        #[clap(long)]
        ownership_account: AccountId,
        /// Bedrock sequencer key (hex) to stake for.
        #[clap(long)]
        sequencer_key: String,
        /// Amount to stake; must be at least the current minimum.
        #[clap(long)]
        amount: u128,
    },
    /// Records a request to release `amount` from `ownership_account` to `destination`.
    /// Moves no balance yet; must leave the account at zero or at/above the minimum.
    UnstakeRequest {
        /// Stake ownership account to release from.
        #[clap(long)]
        ownership_account: AccountId,
        /// Amount to release.
        #[clap(long)]
        amount: u128,
        /// Account credited once `FinalizeUnstake` later runs.
        #[clap(long)]
        destination: AccountId,
    },
}

#[tokio::main]
#[expect(
    clippy::print_stdout,
    reason = "the submitted tx hash on stdout is this binary's output"
)]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let wallet = WalletCore::new_update_chain(
        args.wallet.join("wallet_config.json"),
        args.wallet.join("storage.json"),
        args.wallet.join("statistics.json"),
        None,
    )
    .await
    .context("Failed to open wallet")?;

    let config_id = system_accounts::sequencer_stake_config_account_id();

    let tx_hash = match args.command {
        Command::Stake {
            funding_account,
            ownership_account,
            sequencer_key,
            amount,
        } => {
            let sequencer_key = parse_sequencer_key(&sequencer_key)?;
            let mover_instruction_data = Program::serialize_instruction(
                authenticated_transfer_core::Instruction::Transfer { amount },
            )
            .context("Failed to serialize mover instruction")?;
            let instruction_data =
                Program::serialize_instruction(sequencer_stake_core::Instruction::Stake {
                    self_program_id: programs::sequencer_stake().id(),
                    sequencer_key,
                    amount,
                    mover_account_id: loader_core::immutable_deploy_account_id(
                        programs::authenticated_transfer().id(),
                    ),
                    mover_instruction_data,
                })
                .context("Failed to serialize Stake instruction")?;

            wallet
                .send_pub_tx(
                    vec![
                        AccountIdentity::Public(funding_account),
                        AccountIdentity::Public(ownership_account),
                        AccountIdentity::PublicNoSign(config_id),
                    ],
                    instruction_data,
                    programs::sequencer_stake().id(),
                )
                .await
                .map_err(|err| anyhow!("Failed to submit Stake transaction: {err:?}"))?
        }
        Command::UnstakeRequest {
            ownership_account,
            amount,
            destination,
        } => {
            let instruction_data =
                Program::serialize_instruction(sequencer_stake_core::Instruction::UnstakeRequest {
                    self_program_id: programs::sequencer_stake().id(),
                    amount,
                    destination,
                })
                .context("Failed to serialize UnstakeRequest instruction")?;

            wallet
                .send_pub_tx(
                    vec![
                        AccountIdentity::Public(ownership_account),
                        AccountIdentity::PublicNoSign(config_id),
                    ],
                    instruction_data,
                    programs::sequencer_stake().id(),
                )
                .await
                .map_err(|err| anyhow!("Failed to submit UnstakeRequest transaction: {err:?}"))?
        }
    };

    println!("Submitted transaction {tx_hash}");
    Ok(())
}

fn parse_sequencer_key(hex_key: &str) -> Result<sequencer_stake_core::SequencerKey> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(hex_key, &mut bytes)
        .with_context(|| format!("Invalid hex-encoded key {hex_key}"))?;
    sequencer_stake_core::SequencerKey::new(bytes)
        .with_context(|| format!("{hex_key} is not a valid Ed25519 public key"))
}
