use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use indexer_service::IndexerHandle;
use log::{debug, warn};
use nssa::PrivateKey;
use sequencer_service::{GenesisTransaction, SequencerHandle};
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{
    WalletCore,
    cli::{
        Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        execute_subcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    config::WalletConfigOverrides,
};

use crate::{
    BEDROCK_SERVICE_PORT, BEDROCK_SERVICE_WITH_OPEN_PORT,
    config::{self, INITIAL_PRIVATE_BALANCES_FOR_WALLET},
    private_mention, public_mention,
};

pub async fn setup_bedrock_node() -> Result<(DockerCompose, SocketAddr)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bedrock_compose_path = PathBuf::from(manifest_dir).join("../bedrock/docker-compose.yml");

    let mut compose = DockerCompose::with_auto_client(&[bedrock_compose_path])
            .await
            .context("Failed to setup docker compose for Bedrock")?
            // Setting port to 0 to avoid conflicts between parallel tests, actual port will be retrieved after container is up
            .with_env("PORT", "0");

    #[expect(
        clippy::items_after_statements,
        reason = "This is more readable is this function used just after its definition"
    )]
    async fn up_and_retrieve_port(compose: &mut DockerCompose) -> Result<u16> {
        compose
            .up()
            .await
            .context("Failed to bring up Bedrock services")?;
        let container = compose
            .service(BEDROCK_SERVICE_WITH_OPEN_PORT)
            .with_context(|| {
                format!(
                    "Failed to get Bedrock service container `{BEDROCK_SERVICE_WITH_OPEN_PORT}`"
                )
            })?;

        let ports = container.ports().await.with_context(|| {
            format!(
                "Failed to get ports for Bedrock service container `{}`",
                container.id()
            )
        })?;
        ports
            .map_to_host_port_ipv4(BEDROCK_SERVICE_PORT)
            .with_context(|| {
                format!(
                    "Failed to retrieve host port of {BEDROCK_SERVICE_PORT} container \
                        port for container `{}`, existing ports: {ports:?}",
                    container.id()
                )
            })
    }

    let mut port = None;
    let mut attempt = 0_u32;
    let max_attempts = 5_u32;
    while port.is_none() && attempt < max_attempts {
        attempt = attempt
            .checked_add(1)
            .expect("We check that attempt < max_attempts, so this won't overflow");
        match up_and_retrieve_port(&mut compose).await {
            Ok(p) => {
                port = Some(p);
            }
            Err(err) => {
                warn!(
                    "Failed to bring up Bedrock services: {err:?}, attempt {attempt}/{max_attempts}"
                );
            }
        }
    }
    let Some(port) = port else {
        bail!("Failed to bring up Bedrock services after {max_attempts} attempts");
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    Ok((compose, addr))
}

pub async fn setup_indexer(bedrock_addr: SocketAddr) -> Result<(IndexerHandle, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    debug!(
        "Using temp indexer home at {}",
        temp_indexer_dir.path().display()
    );

    let indexer_config = config::indexer_config(bedrock_addr, temp_indexer_dir.path().to_owned())
        .context("Failed to create Indexer config")?;

    indexer_service::run_server(indexer_config, 0)
        .await
        .context("Failed to run Indexer Service")
        .map(|handle| (handle, temp_indexer_dir))
}

pub async fn setup_sequencer(
    partial: config::SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    genesis_transactions: Vec<GenesisTransaction>,
) -> Result<(SequencerHandle, TempDir)> {
    let temp_sequencer_dir =
        tempfile::tempdir().context("Failed to create temp dir for sequencer home")?;

    debug!(
        "Using temp sequencer home at {}",
        temp_sequencer_dir.path().display()
    );

    let config = config::sequencer_config(
        partial,
        temp_sequencer_dir.path().to_owned(),
        bedrock_addr,
        genesis_transactions,
    )
    .context("Failed to create Sequencer config")?;

    let sequencer_handle = sequencer_service::run(config, 0).await?;

    Ok((sequencer_handle, temp_sequencer_dir))
}

pub fn setup_wallet(
    sequencer_addr: SocketAddr,
    initial_public_accounts: &[(PrivateKey, u128)],
) -> Result<(WalletCore, TempDir, String)> {
    let config = config::wallet_config(sequencer_addr).context("Failed to create Wallet config")?;
    let config_serialized =
        serde_json::to_string_pretty(&config).context("Failed to serialize Wallet config")?;

    let temp_wallet_dir =
        tempfile::tempdir().context("Failed to create temp dir for wallet home")?;

    let config_path = temp_wallet_dir.path().join("wallet_config.json");
    std::fs::write(&config_path, config_serialized)
        .context("Failed to write wallet config in temp dir")?;

    let storage_path = temp_wallet_dir.path().join("storage.json");
    let config_overrides = WalletConfigOverrides::default();

    let wallet_password = "test_pass".to_owned();
    let (mut wallet, _mnemonic) = WalletCore::new_init_storage(
        config_path,
        storage_path,
        Some(config_overrides),
        &wallet_password,
    )
    .context("Failed to init wallet")?;

    for (private_key, _balance) in initial_public_accounts {
        wallet
            .storage_mut()
            .key_chain_mut()
            .add_imported_public_account(private_key.clone());
    }

    wallet
        .store_persistent_data()
        .context("Failed to store wallet persistent data")?;

    Ok((wallet, temp_wallet_dir, wallet_password))
}

pub async fn setup_private_accounts_with_initial_supply(wallet: &mut WalletCore) -> Result<()> {
    for _ in INITIAL_PRIVATE_BALANCES_FOR_WALLET {
        let result = execute_subcommand(
            wallet,
            Command::Account(AccountSubcommand::New(NewSubcommand::Private {
                cci: None,
                label: None,
            })),
        )
        .await
        .context("Failed to create a private account")?;
        let SubcommandReturnValue::RegisterAccount { account_id: _ } = result else {
            bail!("Expected RegisterAccount return value when creating private account");
        };
    }

    let public_account_ids: Vec<_> = wallet
        .storage()
        .key_chain()
        .public_account_ids()
        .map(|(account_id, _idx)| account_id)
        .collect();

    if public_account_ids.len() < INITIAL_PRIVATE_BALANCES_FOR_WALLET.len() {
        bail!(
            "Expected at least {} public accounts in wallet storage, found {}",
            INITIAL_PRIVATE_BALANCES_FOR_WALLET.len(),
            public_account_ids.len()
        );
    }

    let private_account_ids: Vec<_> = wallet
        .storage()
        .key_chain()
        .private_account_ids()
        .map(|(account_id, _idx)| account_id)
        .collect();

    for ((from, to), amount) in public_account_ids
        .into_iter()
        .zip(private_account_ids.into_iter())
        .zip(INITIAL_PRIVATE_BALANCES_FOR_WALLET)
    {
        let result = execute_subcommand(
            wallet,
            Command::AuthTransfer(AuthTransferSubcommand::Send {
                from: public_mention(from),
                to: Some(private_mention(to)),
                to_npk: None,
                to_vpk: None,
                to_identifier: None,
                amount,
            }),
        )
        .await
        .context("Failed to perform initial shielded transfer to private account")?;

        if !matches!(
            result,
            SubcommandReturnValue::PrivacyPreservingTransfer { .. }
        ) {
            bail!(
                "Expected PrivacyPreservingTransfer return value when shielding initial private funds"
            );
        }
    }

    Ok(())
}
