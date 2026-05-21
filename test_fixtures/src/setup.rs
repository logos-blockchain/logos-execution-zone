use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use common::transaction::NSSATransaction;
use indexer_service::IndexerHandle;
use log::{debug, warn};
use nssa::{AccountId, PrivateKey, PublicKey, PublicTransaction, program::Program};
use sequencer_service::{GenesisAction, SequencerHandle};
use sequencer_service_rpc::RpcClient as _;
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{
    AccDecodeData::Decode, PrivacyPreservingAccount, WalletCore, config::WalletConfigOverrides,
};

use crate::{
    BEDROCK_SERVICE_PORT, BEDROCK_SERVICE_WITH_OPEN_PORT,
    config::{self, InitialPrivateAccountForWallet},
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
    genesis_transactions: Vec<GenesisAction>,
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
    initial_private_accounts: &[InitialPrivateAccountForWallet],
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

    for private_account in initial_private_accounts {
        wallet
            .storage_mut()
            .key_chain_mut()
            .add_imported_private_account(
                private_account.key_chain.clone(),
                None,
                private_account.identifier,
                nssa::Account::default(),
            );
    }

    wallet
        .store_persistent_data()
        .context("Failed to store wallet persistent data")?;

    Ok((wallet, temp_wallet_dir, wallet_password))
}

pub async fn setup_public_accounts_with_initial_supply(
    wallet: &WalletCore,
    initial_public_accounts: &[(PrivateKey, u128)],
) -> Result<()> {
    for (private_key, amount) in initial_public_accounts {
        claim_funds_from_vault(
            wallet,
            AccountId::from(&PublicKey::new_from_private_key(private_key)),
            *amount,
        )
        .await
        .context("Failed to claim funds from vault into public account")?;
    }

    Ok(())
}

pub async fn setup_private_accounts_with_initial_supply(
    wallet: &mut WalletCore,
    initial_private_accounts: &[InitialPrivateAccountForWallet],
) -> Result<()> {
    for private_account in initial_private_accounts {
        claim_funds_from_vault_to_private(
            wallet,
            private_account.account_id(),
            private_account.balance,
        )
        .await
        .context("Failed to claim funds from vault into private account")?;
    }

    Ok(())
}

async fn claim_funds_from_vault(
    wallet: &WalletCore,
    owner_id: AccountId,
    amount: u128,
) -> Result<()> {
    let vault_program_id = Program::vault().id();
    let owner_vault_id = vault_core::compute_vault_account_id(vault_program_id, owner_id);

    let nonces = wallet
        .get_accounts_nonces(vec![owner_id])
        .await
        .context("Failed to fetch owner nonce")?;

    let signing_key = wallet
        .storage()
        .key_chain()
        .pub_account_signing_key(owner_id)
        .with_context(|| format!("Missing signing key for public account {owner_id}"))?;

    let message = nssa::public_transaction::Message::try_new(
        vault_program_id,
        vec![owner_id, owner_vault_id],
        nonces,
        vault_core::Instruction::Claim { amount },
    )
    .context("Failed to build vault claim message")?;

    let witness_set = nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    let tx_hash = wallet
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .context("Failed to submit vault claim transaction")?;

    wallet
        .poll_native_token_transfer(tx_hash)
        .await
        .context("Failed to confirm vault claim transaction")?;

    Ok(())
}

async fn claim_funds_from_vault_to_private(
    wallet: &mut WalletCore,
    owner_id: AccountId,
    amount: u128,
) -> Result<()> {
    let Some(_) = wallet.storage().key_chain().private_account(owner_id) else {
        bail!("Missing private account in wallet key chain for account {owner_id}");
    };

    let vault_program = Program::vault();
    let vault_program_id = vault_program.id();
    let owner_vault_id = vault_core::compute_vault_account_id(vault_program_id, owner_id);

    let instruction_data =
        Program::serialize_instruction(vault_core::Instruction::Claim { amount })
            .context("Failed to serialize vault private claim instruction")?;

    let program_with_dependencies =
        nssa::privacy_preserving_transaction::circuit::ProgramWithDependencies::new(
            vault_program,
            HashMap::from([(
                Program::authenticated_transfer_program().id(),
                Program::authenticated_transfer_program(),
            )]),
        );

    let (tx_hash, mut secrets) = wallet
        .send_privacy_preserving_tx(
            vec![
                PrivacyPreservingAccount::PrivateOwned(owner_id),
                PrivacyPreservingAccount::Public(owner_vault_id),
            ],
            instruction_data,
            &program_with_dependencies,
        )
        .await
        .context("Failed to submit private vault claim transaction")?;

    let secret = secrets
        .pop()
        .context("Expected one private output secret for vault claim")?;

    let transfer_tx = wallet
        .poll_native_token_transfer(tx_hash)
        .await
        .context("Failed to confirm private vault claim transaction")?;

    let NSSATransaction::PrivacyPreserving(tx) = transfer_tx else {
        bail!("Expected privacy preserving transaction result for private vault claim");
    };

    wallet
        .decode_insert_privacy_preserving_transaction_results(&tx, &[Decode(secret, owner_id)])
        .context("Failed to decode private vault claim transaction")?;

    wallet
        .store_persistent_data()
        .context("Failed to store wallet data after private vault claim")?;

    Ok(())
}
