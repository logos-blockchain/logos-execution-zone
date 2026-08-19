use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result, anyhow};
use tracing_subscriber::{EnvFilter, fmt};

const FEATURES_DIR_REL: &str = "cucumber_tests/features/";
/// Environment variable controlling the maximum number of concurrent scenarios.
pub const MAX_CUCUMBER_CONCURRENT_SCENARIOS: &str = "MAX_CUCUMBER_CONCURRENT_SCENARIOS";
/// Relative directory used for Cucumber scenario output.
pub const SCENARIO_OUTPUT_DIR_REL: &str = "cucumber_tests/temp";
/// Directory name containing per-scenario artifacts.
pub const ARTEFACTS: &str = "cucumber_artefacts";
const CUCUMBER_RETRIES: &str = "CUCUMBER_RETRIES";
/// Environment variable enabling removal of successful scenario artifacts.
pub const CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL: &str = "CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL";
/// Environment variable selecting an existing node deployment configuration.
pub const CUCUMBER_NODE_CONFIG_OVERRIDE: &str = "CUCUMBER_NODE_CONFIG_OVERRIDE";

/// Installs the Cucumber tracing subscriber using `RUST_LOG` or an `info` default.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _unused = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Returns the path to the features directory.
#[expect(clippy::print_stdout, reason = "Cucumber logs test code")]
pub fn get_feature_path() -> Result<PathBuf> {
    let feature_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FEATURES_DIR_REL);
    if !feature_path.is_dir() {
        return Err(anyhow!(
            "Feature path does not exist: {}",
            feature_path.display()
        ));
    }
    println!("Feature path:      {}", feature_path.display());
    Ok(feature_path)
}

/// Creates the output directory for the current scenario and returns its path.
#[expect(clippy::print_stdout, reason = "Cucumber logs test code")]
pub fn create_scenario_output_dir() -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("failed to determine current directory")?;
    println!("Current directory: {}", current_dir.display());
    let output_dir = current_dir.join(SCENARIO_OUTPUT_DIR_REL);
    fs::create_dir_all(&output_dir).context("failed to create Cucumber output directory")?;
    println!("Output directory: {}", output_dir.display());
    Ok(output_dir)
}

/// Get the number of retries for failed scenarios from the `CUCUMBER_RETRIES`
/// environment variable. Retries are opt-in: an unset variable and an explicit
/// zero both disable retries.
pub fn get_retries() -> Result<Option<usize>> {
    std::env::var_os(CUCUMBER_RETRIES).map_or_else(
        || Ok(None),
        |raw_retries| {
            let retries_value = raw_retries.to_string_lossy();
            let retries = retries_value.parse::<usize>().with_context(|| {
                format!("Invalid value for {CUCUMBER_RETRIES}: '{retries_value}'")
            })?;
            Ok((retries != 0).then_some(retries))
        },
    )
}
