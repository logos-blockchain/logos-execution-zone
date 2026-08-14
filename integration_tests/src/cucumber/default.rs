use std::{fs, path::PathBuf};

use tracing_subscriber::{EnvFilter, fmt};

const FEATURES_DIR_REL: &str = "cucumber_tests/features/";
/// Environment variable controlling the maximum number of concurrent scenarios.
pub const MAX_CUCUMBER_CONCURRENT_SCENARIOS: &str = "MAX_CUCUMBER_CONCURRENT_SCENARIOS";
/// Relative directory used for Cucumber scenario output.
pub const SCENARIO_OUTPUT_DIR_REL: &str = "cucumber_tests/temp";
/// Directory name containing per-scenario artifacts.
pub const ARTEFACTS: &str = "cucumber_artefacts";
const CUCUMBER_RETRIES: &str = "CUCUMBER_RETRIES";
const TF_KEEP_LOGS: &str = "TF_KEEP_LOGS";
const RUST_LOG: &str = "RUST_LOG";
/// Environment variable enabling removal of successful scenario artifacts.
pub const CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL: &str = "CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL";
/// Environment variable selecting an existing node deployment configuration.
pub const CUCUMBER_NODE_CONFIG_OVERRIDE: &str = "CUCUMBER_NODE_CONFIG_OVERRIDE";

/// Installs the Cucumber tracing subscriber using `RUST_LOG` or an `info` default.
pub fn init_tracing() {
    logos_blockchain_testing_framework::env::set_default_env(RUST_LOG, "info");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _unused = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Returns the path to the features directory, panicking if it does not exist.
#[must_use]
#[expect(clippy::print_stdout, reason = "Cucumber logs test code")]
pub fn get_feature_path() -> PathBuf {
    let feature_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FEATURES_DIR_REL);
    if matches!(fs::exists(feature_path.clone()), Ok(true)) {
        println!("Feature path:      {}", feature_path.display());
    } else {
        panic!("Feature path does not exist: {}", feature_path.display());
    }
    feature_path
}

/// Creates the output directory for the current scenario and returns its path.
#[must_use]
#[expect(clippy::print_stdout, reason = "Cucumber logs test code")]
pub fn create_scenario_output_dir() -> PathBuf {
    logos_blockchain_testing_framework::env::set_default_env(TF_KEEP_LOGS, "true");
    let current_dir = std::env::current_dir().expect("should exist");
    println!("Current directory: {}", current_dir.display());
    let output_dir = current_dir.join(SCENARIO_OUTPUT_DIR_REL);
    fs::create_dir_all(output_dir.clone()).expect("should succeed");
    println!("Output directory: {}", output_dir.display());
    output_dir
}

/// Get the number of retries for failed scenarios from the `CUCUMBER_RETRIES`
/// environment variable. Retries are opt-in: an unset variable and an explicit
/// zero both disable retries.
pub fn get_retries() -> Result<Option<usize>, String> {
    std::env::var_os(CUCUMBER_RETRIES).map_or_else(
        || Ok(None),
        |retries| {
            retries
                .to_string_lossy()
                .as_ref()
                .to_owned()
                .parse()
                .map_or_else(
                    |_| {
                        Err(format!(
                            "Invalid value for {CUCUMBER_RETRIES}: '{}'",
                            retries.to_string_lossy()
                        ))
                    },
                    |retries| {
                        if retries == 0 {
                            Ok(None)
                        } else {
                            Ok(Some(retries))
                        }
                    },
                )
        },
    )
}
