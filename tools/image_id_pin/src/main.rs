//! Pins `authenticated_transfer`'s image id as a source constant.
//!
//! Recomputes the id from the built artifact and rewrites
//! `lez/programs/authenticated_transfer/image_id.rs` when it differs, exiting 1
//! so `just build-artifacts` knows to rebuild the guests that embed the
//! constant; 0 when the pin is current, 2 when the artifact or the fragment
//! cannot be read. Converges in one extra pass: the constant is `include!`d
//! only by consumer guests, never by `authenticated_transfer` itself, so the
//! rewrite cannot move the id it pins.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "regen tool: the refresh outcome is its user-facing output"
)]

use std::{env, fs, process::ExitCode};

const DEFAULT_BIN: &str = "artifacts/lez/programs/authenticated_transfer.bin";
const FRAGMENT: &str = "lez/programs/authenticated_transfer/image_id.rs";

// The recipe rebuilds the consumers on this code and only this code.
const REFRESHED: u8 = 1;
const FAILED: u8 = 2;

fn main() -> ExitCode {
    match refresh() {
        Ok(None) => {
            println!("authenticated_transfer image id pin is current");
            ExitCode::SUCCESS
        }
        Ok(Some(image_id)) => {
            println!("authenticated_transfer image id pin refreshed to {image_id:?}");
            ExitCode::from(REFRESHED)
        }
        Err(err) => {
            eprintln!("image id pin: {err}");
            ExitCode::from(FAILED)
        }
    }
}

/// The id the fragment was rewritten to, or `None` when it already held it.
fn refresh() -> Result<Option<[u32; 8]>, String> {
    // An override for local verification: point at an extracted or
    // harness-built ELF instead of the committed artifact.
    let bin_path = env::args().nth(1).unwrap_or_else(|| DEFAULT_BIN.into());
    let elf = fs::read(&bin_path).map_err(|err| format!("read {bin_path}: {err}"))?;
    let image_id: [u32; 8] = risc0_binfmt::compute_image_id(&elf)
        .map_err(|err| format!("compute the image id of {bin_path}: {err}"))?
        .into();

    let fragment = fs::read_to_string(FRAGMENT).map_err(|err| format!("read {FRAGMENT}: {err}"))?;
    let start = fragment
        .find("pub const AUTHENTICATED_TRANSFER_IMAGE_ID")
        .ok_or_else(|| format!("{FRAGMENT} does not declare the constant"))?;
    let (head, declaration) = fragment.split_at(start);
    if declaration.lines().count() != 1 {
        return Err(format!(
            "the constant must be {FRAGMENT}'s last line: a rewrite drops what follows it"
        ));
    }

    let rewritten =
        format!("{head}pub const AUTHENTICATED_TRANSFER_IMAGE_ID: [u32; 8] = {image_id:?};\n");
    if rewritten == fragment {
        return Ok(None);
    }
    fs::write(FRAGMENT, rewritten).map_err(|err| format!("rewrite {FRAGMENT}: {err}"))?;
    Ok(Some(image_id))
}
