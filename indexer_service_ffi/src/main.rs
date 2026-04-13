use std::{ffi::{CString, c_char}, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use indexer_ffi::api::lifecycle::InitializedIndexerServiceFFIResult;
use log::info;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(name = "config")]
    config_path: PathBuf,
    #[clap(short, long, default_value = "8779")]
    port: u16,
}

unsafe extern "C" {
    fn start_indexer(config_path: *const c_char, port: u16) -> InitializedIndexerServiceFFIResult;
}

fn main() -> Result<()> {
    env_logger::init();

    let Args { config_path, port } = Args::parse();

    let res =
            unsafe { start_indexer(CString::new(config_path.to_str().unwrap())?.as_ptr(), port) };

    if res.error.is_error() {
        anyhow::bail!("Indexer FFI error {:?}", res.error);
    }

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
        info!("Running...");
    }
}
