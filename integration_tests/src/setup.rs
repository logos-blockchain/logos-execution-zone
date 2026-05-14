use std::{
    ffi::{CString, c_char},
    fs::File,
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
};

use anyhow::{Context as _, Result, bail};
use indexer_ffi::{IndexerServiceFFI, api::lifecycle::InitializedIndexerServiceFFIResult};
use indexer_service::IndexerHandle;
use log::{debug, warn};
use sequencer_service::SequencerHandle;
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{WalletCore, config::WalletConfigOverrides};

use crate::{BEDROCK_SERVICE_PORT, BEDROCK_SERVICE_WITH_OPEN_PORT, config};

unsafe extern "C" {
    fn start_indexer(config_path: *const c_char, port: u16) -> InitializedIndexerServiceFFIResult;
}

pub(crate) async fn setup_bedrock_node() -> Result<(DockerCompose, SocketAddr)> {
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

pub(crate) async fn setup_indexer(
    bedrock_addr: SocketAddr,
    initial_data: &config::InitialData,
) -> Result<(IndexerHandle, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    debug!(
        "Using temp indexer home at {}",
        temp_indexer_dir.path().display()
    );

    let indexer_config = config::indexer_config(
        bedrock_addr,
        temp_indexer_dir.path().to_owned(),
        initial_data,
    )
    .context("Failed to create Indexer config")?;

    indexer_service::run_server(indexer_config, 0)
        .await
        .context("Failed to run Indexer Service")
        .map(|handle| (handle, temp_indexer_dir))
}

pub(crate) async fn setup_sequencer(
    partial: config::SequencerPartialConfig,
    bedrock_addr: SocketAddr,
    indexer_addr: SocketAddr,
    initial_data: &config::InitialData,
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
        indexer_addr,
        initial_data,
    )
    .context("Failed to create Sequencer config")?;

    let sequencer_handle = sequencer_service::run(config, 0).await?;

    Ok((sequencer_handle, temp_sequencer_dir))
}

pub(crate) async fn setup_wallet(
    sequencer_addr: SocketAddr,
    initial_data: &config::InitialData,
) -> Result<(WalletCore, TempDir, String)> {
    let config = config::wallet_config(sequencer_addr, initial_data)
        .context("Failed to create Wallet config")?;
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
    let (wallet, _mnemonic) = WalletCore::new_init_storage(
        config_path,
        storage_path,
        Some(config_overrides),
        &wallet_password,
    )
    .context("Failed to init wallet")?;
    wallet
        .store_persistent_data()
        .await
        .context("Failed to store wallet persistent data")?;

    Ok((wallet, temp_wallet_dir, wallet_password))
}

pub(crate) fn setup_indexer_ffi(
    bedrock_addr: SocketAddr,
    initial_data: &config::InitialData,
) -> Result<(IndexerServiceFFI, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    debug!(
        "Using temp indexer home at {}",
        temp_indexer_dir.path().display()
    );

    let indexer_config = config::indexer_config(
        bedrock_addr,
        temp_indexer_dir.path().to_owned(),
        initial_data,
    )
    .context("Failed to create Indexer config")?;

    let config_json = serde_json::to_vec(&indexer_config)?;
    let config_path = temp_indexer_dir.path().join("indexer_config.json");
    let mut file = File::create(config_path.as_path())?;
    file.write_all(&config_json)?;
    file.flush()?;

    let res =
            // SAFETY: lib function ensures validity of value.
            unsafe { start_indexer(CString::new(config_path.to_str().unwrap())?.as_ptr(), 0) };

    if res.error.is_error() {
        anyhow::bail!("Indexer FFI error {:?}", res.error);
    }

    Ok((
        // SAFETY: lib function ensures validity of value.
        unsafe { std::ptr::read(res.value) },
        temp_indexer_dir,
    ))
}
