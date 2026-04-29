#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout is expected and convenient"
)]

use anyhow::{Context as _, Result};
use clap::{CommandFactory as _, Parser as _};
use wallet::{
    WalletCore,
    cli::{Args, execute_continuous_run, execute_subcommand, read_password_from_stdin},
    config::WalletConfigOverrides,
    helperfunctions::{fetch_config_path, fetch_persistent_storage_path},
};

// TODO #169: We have sample configs for sequencer, but not for wallet
// TODO #168: Why it requires config as a directory? Maybe better to deduce directory from config
// file path?
// TODO #172: Why it requires config as env var while sequencer_service accepts as
// argument?
#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        continuous_run,
        auth,
        command,
    } = Args::parse();

    env_logger::init();

    let config_path = fetch_config_path().context("Could not fetch config path")?;
    let storage_path =
        fetch_persistent_storage_path().context("Could not fetch persistent storage path")?;

    // Override basic auth if provided via CLI
    let config_overrides = WalletConfigOverrides {
        basic_auth: auth.map(|auth| auth.parse()).transpose()?.map(Some),
        ..Default::default()
    };

    if let Some(command) = command {
        let mut wallet = if storage_path.exists() {
            WalletCore::new_update_chain(config_path, storage_path, Some(config_overrides))?
        } else {
            // TODO: Maybe move to `WalletCore::from_env()` or similar?

            println!("Persistent storage not found, need to execute setup");

            let password = read_password_from_stdin()?;
            let (wallet, mnemonic) = WalletCore::new_init_storage(
                config_path,
                storage_path,
                Some(config_overrides),
                &password,
            )?;

            println!();
            println!("IMPORTANT: Write down your recovery phrase and store it securely.");
            println!("This is the only way to recover your wallet if you lose access.");
            println!();
            println!("Recovery phrase:");
            println!("  {mnemonic}");
            println!();

            wallet.store_persistent_data().await?;
            wallet
        };
        let _output = execute_subcommand(&mut wallet, command).await?;
        Ok(())
    } else if continuous_run {
        let mut wallet =
            WalletCore::new_update_chain(config_path, storage_path, Some(config_overrides))?;
        execute_continuous_run(&mut wallet).await
    } else {
        let help = Args::command().render_long_help();
        println!("{help}");
        Ok(())
    }
}
