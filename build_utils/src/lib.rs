//! Utilities for build-scripts.

use std::{env, fmt::Write as _, fs, path::PathBuf};

use anyhow::{Context as _, Result, bail};

/// Include artifact binaries as byte arrays and their corresponding image IDs as u32 arrays in a
/// generated Rust module.
///
/// The `artifacts_sub_dir` parameter specifies the subdirectory under `artifacts/`.
///
/// Caller should include resulting module as follows:
///
/// ```
/// mod guests {
///     include!(concat!(env!("OUT_DIR"), "/artifacts_sub_dir/mod.rs"));
/// }
/// ```
pub fn include_artifacts(artifacts_sub_dir: &str) -> Result<()> {
    // Resolved at build-script runtime from the invoking crate, not at compile
    // time: `env!` would bake in the path of whichever checkout compiled this
    // rlib first, and with a shared cargo target dir every other worktree then
    // embeds that checkout's artifacts instead of its own.
    let invoking_manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = invoking_manifest_dir
        .ancestors()
        .find(|dir| dir.join("artifacts").is_dir())
        .context("no artifacts/ directory above the invoking crate")?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let mod_dir = out_dir.join(artifacts_sub_dir);
    let mod_file = mod_dir.join("mod.rs");
    let artifacts_dir = workspace_root.join(format!("artifacts/{artifacts_sub_dir}/"));

    println!("cargo:rerun-if-changed={}", artifacts_dir.display());

    let bins = fs::read_dir(&artifacts_dir)
        .with_context(|| {
            format!(
                "Failed to read {} artifacts directory",
                artifacts_dir.display()
            )
        })?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
        .collect::<Vec<_>>();

    if bins.is_empty() {
        bail!("No .bin files found in {}", artifacts_dir.display());
    }

    fs::create_dir_all(&mod_dir)
        .with_context(|| format!("Failed to create directory {}", mod_dir.display()))?;
    let mut src = String::new();
    for entry in bins {
        let path = entry.path();
        let name = path.file_stem().unwrap().to_string_lossy();
        let bytecode =
            fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?;
        let image_id: [u32; 8] = risc0_binfmt::compute_image_id(&bytecode)
            .with_context(|| format!("Failed to compute image ID for {}", path.display()))?
            .into();
        write!(
            src,
            "pub const {}_ELF: &[u8] = include_bytes!(r#\"{}\"#);\n\
             #[expect(clippy::unreadable_literal, reason = \"Generated image IDs from risc0 are cryptographic hashes represented as u32 arrays\")]\n\
             pub const {}_ID: [u32; 8] = {:?};\n",
            name.to_uppercase(),
            path.display(),
            name.to_uppercase(),
            image_id
        )?;
    }
    fs::write(&mod_file, src).with_context(|| format!("Failed to write {}", mod_file.display()))?;
    println!("cargo:warning=Generated module at {}", mod_file.display());

    Ok(())
}
