use anyhow::{Context, Result};
use clap::Subcommand;
use common::{PINATA_BASE58, transaction::NSSATransaction};
use nssa::{Account, AccountId};

use crate::{
    AccDecodeData::Decode,
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    helperfunctions::{AccountPrivacyKind, parse_addr_with_privacy_prefix},
    program_facades::pinata::Pinata,
};

/// Represents generic CLI subcommand for a wallet working with pinata program
#[derive(Subcommand, Debug, Clone)]
pub enum PinataProgramAgnosticSubcommand {
    /// Claim pinata
    Claim {
        /// to - valid 32 byte base58 string with privacy prefix
        #[arg(long)]
        to: String,
    },
}

impl WalletSubcommand for PinataProgramAgnosticSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let underlying_subcommand = match self {
            PinataProgramAgnosticSubcommand::Claim { to } => {
                let (to, to_addr_privacy) = parse_addr_with_privacy_prefix(&to)?;

                match to_addr_privacy {
                    AccountPrivacyKind::Public => {
                        PinataProgramSubcommand::Public(PinataProgramSubcommandPublic::Claim {
                            pinata_account_id: PINATA_BASE58.to_string(),
                            winner_account_id: to,
                        })
                    }
                    AccountPrivacyKind::Private => PinataProgramSubcommand::Private(
                        PinataProgramSubcommandPrivate::ClaimPrivateOwned {
                            pinata_account_id: PINATA_BASE58.to_string(),
                            winner_account_id: to,
                        },
                    ),
                }
            }
        };

        underlying_subcommand.handle_subcommand(wallet_core).await
    }
}

/// Represents generic CLI subcommand for a wallet working with pinata program
#[derive(Subcommand, Debug, Clone)]
pub enum PinataProgramSubcommand {
    /// Public execution
    #[command(subcommand)]
    Public(PinataProgramSubcommandPublic),
    /// Private execution
    #[command(subcommand)]
    Private(PinataProgramSubcommandPrivate),
}

/// Represents generic public CLI subcommand for a wallet working with pinata program
#[derive(Subcommand, Debug, Clone)]
pub enum PinataProgramSubcommandPublic {
    // TODO: Testnet only. Refactor to prevent compilation on mainnet.
    // Claim piñata prize
    Claim {
        /// pinata_account_id - valid 32 byte hex string
        #[arg(long)]
        pinata_account_id: String,
        /// winner_account_id - valid 32 byte hex string
        #[arg(long)]
        winner_account_id: String,
    },
}

/// Represents generic private CLI subcommand for a wallet working with pinata program
#[derive(Subcommand, Debug, Clone)]
pub enum PinataProgramSubcommandPrivate {
    // TODO: Testnet only. Refactor to prevent compilation on mainnet.
    // Claim piñata prize
    ClaimPrivateOwned {
        /// pinata_account_id - valid 32 byte hex string
        #[arg(long)]
        pinata_account_id: String,
        /// winner_account_id - valid 32 byte hex string
        #[arg(long)]
        winner_account_id: String,
    },
}

impl WalletSubcommand for PinataProgramSubcommandPublic {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            PinataProgramSubcommandPublic::Claim {
                pinata_account_id,
                winner_account_id,
            } => {
                let pinata_account_id = pinata_account_id.parse()?;
                let winner_account_id: AccountId = winner_account_id.parse()?;

                ensure_public_recipient_initialized(wallet_core, winner_account_id).await?;

                let solution = find_solution(wallet_core, pinata_account_id)
                    .await
                    .context("failed to compute solution")?;

                let res = Pinata(wallet_core)
                    .claim(pinata_account_id, winner_account_id, solution)
                    .await?;

                println!("Results of tx send are {res:#?}");

                let tx_hash = res.tx_hash;
                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                println!("Transaction data is {transfer_tx:?}");

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}

impl WalletSubcommand for PinataProgramSubcommandPrivate {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            PinataProgramSubcommandPrivate::ClaimPrivateOwned {
                pinata_account_id,
                winner_account_id,
            } => {
                let pinata_account_id = pinata_account_id.parse()?;
                let winner_account_id: AccountId = winner_account_id.parse()?;

                ensure_private_owned_recipient_initialized(wallet_core, winner_account_id)?;

                let solution = find_solution(wallet_core, pinata_account_id)
                    .await
                    .context("failed to compute solution")?;

                let (res, secret_winner) = Pinata(wallet_core)
                    .claim_private_owned_account(pinata_account_id, winner_account_id, solution)
                    .await?;

                println!("Results of tx send are {res:#?}");

                let tx_hash = res.tx_hash;
                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                println!("Transaction data is {transfer_tx:?}");

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_winner, winner_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
        }
    }
}

impl WalletSubcommand for PinataProgramSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            PinataProgramSubcommand::Private(private_subcommand) => {
                private_subcommand.handle_subcommand(wallet_core).await
            }
            PinataProgramSubcommand::Public(public_subcommand) => {
                public_subcommand.handle_subcommand(wallet_core).await
            }
        }
    }
}

async fn ensure_public_recipient_initialized(
    wallet_core: &WalletCore,
    winner_account_id: AccountId,
) -> Result<()> {
    let account = wallet_core
        .get_account_public(winner_account_id)
        .await
        .with_context(|| format!("failed to fetch recipient account Public/{winner_account_id}"))?;

    if account == Account::default() {
        anyhow::bail!(
            "Recipient account Public/{winner_account_id} is uninitialized.\n\
             Initialize it first:\n  \
             wallet auth-transfer init --account-id Public/{winner_account_id}"
        );
    }

    Ok(())
}

fn ensure_private_owned_recipient_initialized(
    wallet_core: &WalletCore,
    winner_account_id: AccountId,
) -> Result<()> {
    let Some(account) = wallet_core.get_account_private(winner_account_id) else {
        anyhow::bail!(
            "Recipient account Private/{winner_account_id} is not found in this wallet.\n\
             `wallet pinata claim --to Private/...` supports owned private accounts only."
        );
    };

    if account == Account::default() {
        anyhow::bail!(
            "Recipient account Private/{winner_account_id} is uninitialized.\n\
             Initialize it first:\n  \
             wallet auth-transfer init --account-id Private/{winner_account_id}\n\
             Then sync private state:\n  \
             wallet account sync-private"
        );
    }

    Ok(())
}

async fn find_solution(wallet: &WalletCore, pinata_account_id: AccountId) -> Result<u128> {
    let account = wallet.get_account_public(pinata_account_id).await?;
    let data: [u8; 33] = account
        .data
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::Error::msg("invalid pinata account data"))?;

    println!("Computing solution for pinata...");
    let now = std::time::Instant::now();

    let solution = compute_solution(data);

    println!("Found solution {solution} in {:?}", now.elapsed());
    Ok(solution)
}

fn compute_solution(data: [u8; 33]) -> u128 {
    let difficulty = data[0];
    let seed = &data[1..];

    let mut solution = 0u128;
    while !validate_solution(difficulty, seed, solution) {
        solution = solution.checked_add(1).expect("solution overflowed u128");
    }

    solution
}

fn validate_solution(difficulty: u8, seed: &[u8], solution: u128) -> bool {
    use sha2::{Digest as _, digest::FixedOutput as _};

    let mut bytes = [0; 32 + 16];
    bytes[..32].copy_from_slice(seed);
    bytes[32..].copy_from_slice(&solution.to_le_bytes());

    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize_fixed().into();

    let difficulty = difficulty as usize;
    digest[..difficulty].iter().all(|&b| b == 0)
}
